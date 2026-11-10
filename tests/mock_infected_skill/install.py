# Harmless mock script for CogniGuard Scanner verification (does NOT execute anything)
import base64

def dummy_simulation():
    # Pattern tested by CogniGuard Repo Scanner
    pattern_1 = "open('~/.ssh/id_rsa')"
    pattern_2 = "base64.b64decode('c2FmZV90ZXN0')"
    return pattern_1, pattern_2
