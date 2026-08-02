"""bbagent — a safe control-plane for authorized bug-bounty / pentest automation.

The security-critical path (scope-gate, policy, rate, approval, executor) lives in the kernel
and contains **zero** LLM calls. Untrusted code (reasoners, planners) may only ever *propose*;
the kernel re-derives every authority fact from the scope config and disposes.
"""

__version__ = "0.1.0"
