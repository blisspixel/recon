"""Compatibility shim for MCP lookup tool module.

The implementation lives in the package-local module imported below.
"""

from __future__ import annotations

import importlib
import sys

_impl = importlib.import_module("recon_tool.server.lookup")

_SHIM_NAME = __name__
_PARENT_NAME, _, _CHILD_NAME = _SHIM_NAME.rpartition(".")
globals().update(_impl.__dict__)
if _PARENT_NAME:
    setattr(sys.modules[_PARENT_NAME], _CHILD_NAME, _impl)
sys.modules[_SHIM_NAME] = _impl
