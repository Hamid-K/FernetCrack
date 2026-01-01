#!/usr/bin/env python3
"""
Extract Fernet tokens from common files by scanning for known markers or tokens.
Supports PNG LSB (Stegano format) when Pillow is available.
Writes token to fernet_token.txt in the current working directory.
"""
import argparse
import base64
import re

try:
    from PIL import Image
except Exception:
    Image = None

START = b"<<--STEG_START-->>"
END = b"<<--STEG_END-->>"
TOKEN_RE = re.compile(r"gAAAAA[0-9A-Za-z_-]+")


def extract_png(path):
    # Stegano-style LSB stream: "<len>:<token>"
    if Image is None:
        raise RuntimeError("Pillow is required: pip install pillow")
    img = Image.open(path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    pixels = list(img.getdata())
    bits = []
    for r, g, b, *rest in pixels:
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    text = out.decode("latin1", errors="ignore")
    m = re.match(r"^(\d{1,6}):(.*)", text)
    if not m:
        raise RuntimeError("No Stegano-style prefix found")
    msg_len = int(m.group(1))
    token = m.group(2)[:msg_len]
    return token


def extract_mp4(path):
    # Trailer-based stego with explicit START/END markers.
    data = open(path, "rb").read()
    s = data.find(START)
    e = data.find(END)
    if s == -1 or e == -1:
        raise RuntimeError("No STEG markers found")
    content = data[s + len(START):e].strip().decode("utf-8", errors="ignore")
    idx = content.find("gAAAAA")
    if idx == -1:
        raise RuntimeError("No Fernet token found in STEG block")
    b64_name = content[:idx].replace("\x00", "")
    try:
        name = base64.b64decode(b64_name).decode("utf-8", errors="ignore")
        print("embedded filename:", name)
    except Exception:
        pass
    token = content[idx:]
    return token


def looks_like_fernet(token):
    if not token.startswith("gAAAAA"):
        return False
    try:
        raw = base64.urlsafe_b64decode(token + "==")
    except Exception:
        return False
    return len(raw) > 0 and raw[0] == 0x80


def extract_from_markers_or_scan(path, list_all=False, select_index=None):
    data = open(path, "rb").read()
    # Case-insensitive marker search
    upper = data.upper()
    s = upper.find(START.upper())
    e = upper.find(END.upper())
    if s != -1 and e != -1:
        content = data[s + len(START):e].strip().decode("utf-8", errors="ignore")
        idx = content.find("gAAAAA")
        if idx == -1:
            raise RuntimeError("STEG markers found, but no Fernet token detected")
        b64_name = content[:idx].replace("\x00", "")
        try:
            name = base64.b64decode(b64_name).decode("utf-8", errors="ignore")
            print("embedded filename:", name)
        except Exception:
            pass
        token = content[idx:]
        if not looks_like_fernet(token):
            raise RuntimeError("STEG token did not match Fernet structure")
        if list_all:
            return [(token, s + len(START) + idx)]
        return token

    # Fallback: scan raw data for Fernet-like tokens.
    text = data.decode("latin1", errors="ignore")
    matches = []
    for m in TOKEN_RE.finditer(text):
        tok = m.group(0)
        if looks_like_fernet(tok):
            matches.append((tok, m.start()))
    if not matches:
        raise RuntimeError("No STEG markers or Fernet token found")
    if list_all:
        return matches
    if select_index is not None:
        if select_index < 0 or select_index >= len(matches):
            raise RuntimeError("Index out of range for detected tokens")
        return matches[select_index][0]
    return matches[0][0]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract Fernet tokens from files (markers, raw scan, PNG LSB)."
    )
    parser.add_argument("file", help="Input file (.png or other)")
    parser.add_argument(
        "-o",
        "--out",
        default="fernet_token.txt",
        help="Output file for token (default: fernet_token.txt)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all detected tokens with offsets",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=None,
        help="Select token by index (from --list output)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    path = args.file
    if path.lower().endswith(".png"):
        try:
            token = extract_png(path)
        except Exception:
            token = extract_from_markers_or_scan(path, list_all=args.list, select_index=args.index)
    else:
        token = extract_from_markers_or_scan(path, list_all=args.list, select_index=args.index)

    if args.list:
        if isinstance(token, list):
            for i, (tok, off) in enumerate(token):
                print(f"[{i}] offset={off} length={len(tok)}")
            if args.index is None:
                return
            token = token[args.index][0]
        else:
            print(f"[0] offset=lsb length={len(token)}")
            if args.index is None or args.index == 0:
                pass
            else:
                raise RuntimeError("Index out of range for detected tokens")

    out = args.out
    with open(out, "w", encoding="utf-8") as f:
        f.write(token)
    print("wrote", out)
    print("token length:", len(token))


if __name__ == "__main__":
    main()
