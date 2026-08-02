"""The trusted kernel: the only holder of subprocess, sockets, and DB writes.

Broker -> Scope-Gate -> Policy -> Rate Governor -> Approval -> Executor. Every authority fact is
re-derived here from the scope config; an LLM/reasoner proposal carries no authority.
"""

from bbagent.kernel.rate import RateGovernor

__all__ = ["RateGovernor"]
