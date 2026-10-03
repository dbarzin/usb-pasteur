"""Harmless test samples, generated at test time.

The EICAR test file is stored encoded (base64 of the bytes XOR 0x55), so that
no antivirus flags the repository on developer machines or in CI.
"""

from __future__ import annotations

import base64

_EICAR_ENCODED = (
    "DWAadAVwFRQFDmEJBQ8NYGF9BQt8YhYWfGIocRAcFhQHeAYBFBsRFAcReBQbARwDHAcABngBEAYBeBMcGRB0cR1+HX8="
)


def eicar() -> bytes:
    return bytes(b ^ 0x55 for b in base64.b64decode(_EICAR_ENCODED))
