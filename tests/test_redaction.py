from core.security import redact_tokens

def test_redaction():
 assert '[REDACTED]' in redact_tokens('https://x?token=abcdef')
