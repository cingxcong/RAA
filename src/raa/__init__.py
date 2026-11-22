"""RAA - Reverse Android Anything.

The package is organized as one analysis core with multiple generated
surfaces: MCP, REST, CLI and a Python SDK.
"""

from raa.compat import ensure_sandbox_compatibility
from raa.version import PROTOCOL_VERSION, __version__

ensure_sandbox_compatibility()

__all__ = ["PROTOCOL_VERSION", "__version__"]
