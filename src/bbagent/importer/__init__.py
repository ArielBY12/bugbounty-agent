"""Scope importer — derive a scope draft from a HackerOne / Bugcrowd program.

The importer only fills ``in_scope`` / ``out_of_scope`` / notes. It ALWAYS leaves
``authorized: false`` and ``active_actions_allowed: false`` — a human must review the derived
scope and flip those switches before any active step (SAF-1/SAF-2). Recon (passive) may run on the
draft immediately, since passive OSINT makes zero target contact.
"""

from bbagent.importer.core import (
    ImportError_,
    ScopeDraft,
    import_brief,
    import_from_file,
    import_from_url,
    looks_like_brief,
    parse_brief,
    parse_bugcrowd,
    parse_hackerone,
    structure_brief_with_llm,
)

__all__ = [
    "ImportError_",
    "ScopeDraft",
    "import_brief",
    "import_from_file",
    "import_from_url",
    "looks_like_brief",
    "parse_brief",
    "parse_bugcrowd",
    "parse_hackerone",
    "structure_brief_with_llm",
]
