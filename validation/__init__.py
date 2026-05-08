"""Live validation workspace — runners, gap analysis, and the agentic UX harness.

This file exists so static-analysis tooling treats ``validation`` as a
regular package; the workspace was previously an implicit namespace
package, which works at runtime but defeats import resolution in
pyright/pylance. The runtime contract (``python -m validation.<name>``)
is unchanged.
"""
