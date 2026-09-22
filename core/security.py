import re

def redact_tokens(text):
    s=str(text)
    s=re.sub(r'(token=)[^&\s]+',r'\1[REDACTED]',s,flags=re.I)
    return s
