# ADR-0010: Evidence-gated native acceleration

- **Status:** Accepted
- **Date:** 2026-07-11

## Context

recon is a local Python CLI, library, JSON producer, and stdio MCP server. Its
normal lookup path waits on public DNS, certificate-transparency providers, and
identity endpoints. The current universal wheel installs without a compiler on
Python 3.11 through 3.14 across Windows, macOS, and Linux. Main CI verifies
matching wheel and sdist hashes across two builds within one resolved Ubuntu
job. The release pipeline builds, audits, attests, and publishes one pure-Python
wheel and one source distribution. Cross-environment byte identity is not
claimed.

A July 2026 CPU-only characterization on Python 3.14.4 found several bounded
local costs. Cold loading the 847-entry YAML catalog took a 476 ms median,
matching 1,000 synthetic TXT values against 298 rules took 348 ms, one shipped
Bayesian inference took 11 ms, and a 1,000-service panel render took 17 ms. CT
graph cost varied from 25 ms for 50 synthetic nodes to 440 ms and 12.8 MiB of
traced allocation for the exact 1,000-entry, 20-SAN dense fixture. These are
synthetic medians from one Windows workstation, not end-to-end product SLOs.
Profiling attributed the largest costs to YAML parsing, repeated regex dispatch,
exact factor arithmetic and uncertainty calculations, pair expansion, and
repeated NetworkX partition-stability runs.

The repository has no tensor, GPU, model-serving, hosted control-plane, or
independently deployable worker workload. Adding Rust, Go, or Mojo would add a
compiler, dependency graph, quality toolchain, artifact matrix, SBOM surface,
and release path. A native Python extension would also replace the current
single universal-wheel assumption with platform-specific artifacts. Python
3.14 free threading is supported but optional, and it does not accelerate an
async workflow unless recon introduces and validates parallel CPU work.

## Decision

We will keep the default runtime and distribution pure Python. Performance work
will follow this order:

1. Establish a dated, production-shaped stage baseline that separates network
   wait, blocked-loop time, local CPU, allocation, serialization, and startup.
2. Improve algorithms, caching, batching, and allocation behavior in Python.
3. Consider one optional Rust extension only if a stable, deterministic,
   coarse-grained capability still violates a declared product budget.

Rust is the only current polyglot research candidate because an optional PyO3
extension could preserve the public Python API and keep a Python reference
implementation for differential testing and fallback. It is not approved for
implementation by this ADR. The numeric eligibility floors below are
conservative provisional governance limits, not product SLOs. They require a
native component to produce enough benefit to repay platform-wheel, toolchain,
SBOM, provenance, and maintenance costs. The production-shaped baseline will
replace them with operation-specific budgets before any prototype. A prototype
must first satisfy all of these gates:

The 250 ms floor excludes micro-optimization theater, the 20 percent share
requires Amdahl-relevant end-to-end pressure, and the promotion deltas must be
large enough to exceed ordinary host noise and repay recurring packaging work.

- After Python optimization, the candidate stage remains above 250 ms p95 on a
  representative warm fixture or accounts for at least 20 percent of warm
  end-to-end p95 after network wait is separated.
- The Python implementation has received a measured algorithmic and caching
  pass and still misses its declared budget.
- The prototype improves stage p95 by at least 3 times and also improves warm
  end-to-end p95 by at least 20 percent, sustained batch throughput by at least
  25 percent, or peak allocation by at least 30 percent.
- CLI, library, JSON, MCP, cache, cancellation, timeout, and error behavior are
  identical under differential, property, malformed-input, and fallback tests.
- Every advertised platform has a prebuilt wheel. Normal installation must not
  require a Rust compiler, and native load failure must visibly use the Python
  fallback without changing results.
- Native formatting, compiler warnings, tests, dependency audit, fuzzing,
  meaningful coverage, reproducibility, multi-ecosystem SBOM, provenance, and
  artifact verification are blocking local and CI gates.
- The complete native release matrix is maintainable within the project's
  existing release discipline and has a documented rollback path.

Go is deferred unless recon later acquires a separately valuable hosted or
worker boundary with independent scaling, lifecycle, or failure isolation. A
Go binary or service is not an optimization for the current local product.

Mojo is rejected for the current scope. recon has no accelerator kernel. The
official 1.0 beta guidance says core language stabilization is still in progress
and not all library APIs will be stable at 1.0; native Windows support is also
absent. The small exact Bayesian network is deliberately auditable and does not
justify a tensor or GPU runtime.

Python 3.14 free-threaded compatibility remains in CI. It is a compatibility
surface, not a performance claim. Threading changes require the same blocked-I/O
or CPU-stage evidence as any other architecture change.

## Consequences

The one-command installation, universal wheel, cross-platform support, current
supply-chain controls, and Python-level auditability remain intact. The first
performance work can target catalog loading, regex dispatch, and repeated
inference calculations without a cross-language boundary.

The project accepts that a future measured hotspot may require a deliberate
native build and release investment. Crossing that boundary will require a new
ADR that names the selected capability, package topology, supported artifact
matrix, toolchain pins, and rollback mechanism. Go or Mojo would require a new
product need and a separate architecture decision.

The characterization and current official-source constraints are maintained in
[performance.md](../performance.md). This ADR does not establish an SLO and does
not authorize a native implementation.
