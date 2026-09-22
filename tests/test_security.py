from core.security import redact_tokens

def test_redact():
 assert "[REDACTED]" in redact_tokens("https://x?token=abc")
