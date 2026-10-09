"""Optional LLM forensic analyst (spec 29).

Strictly downstream of the deterministic engines, and strictly read-only. The
system is fully operational with the provider disabled, which is the default.
"""

from llm.analyst import explain_record
from llm.provider import LLMProvider, LLMResponse, build_provider

__all__ = ["LLMProvider", "LLMResponse", "build_provider", "explain_record"]
