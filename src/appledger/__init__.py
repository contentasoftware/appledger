"""AppLedger honest check: security feedback in plain language for apps built with AI."""

from .scanner import ScanError, check, doctor

__version__ = "0.1.0"
__all__ = ["ScanError", "check", "doctor", "__version__"]
