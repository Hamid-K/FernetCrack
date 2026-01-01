rule fernet_token_like
{
  meta:
    description = "Detect Fernet-like tokens (URL-safe base64, gAAAAA prefix)"
    author = "Hamid Kashfi (X: @hkashfi), Codex"
    confidence = "high, but not cryptographically validated"
  strings:
    $fernet = /gAAAAA[0-9A-Za-z_-]{74,}/
  condition:
    $fernet
}
