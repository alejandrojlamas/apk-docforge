from __future__ import annotations

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.services.discovery import search_apps


class SourceDiscoveryAgent(BaseAgent):
    name = "SourceDiscoveryAgent"
    output_files = ("source_candidates.json", "source_policy_decisions.json")

    def run(self) -> AgentContext:
        query = str(self.context.data.get("search_query", ""))
        sources = self.context.data.get("search_sources", ["fdroid", "github"])
        result = search_apps(query, [str(source) for source in sources], persist=True)
        self.write_json(
            "source_candidates.json",
            {"schema_version": "1.0", "candidates": result["candidates"]},
        )
        self.write_json(
            "source_policy_decisions.json",
            {"schema_version": "1.0", "decisions": result["policy_decisions"], "errors": result["errors"]},
        )
        self.context.data["source_candidates"] = result["candidates"]
        self.context.data["source_policy_decisions"] = result["policy_decisions"]
        return self.context
