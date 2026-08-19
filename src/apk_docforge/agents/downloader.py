from __future__ import annotations

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.services.downloader import download_candidate


class DownloadProvenanceAgent(BaseAgent):
    name = "DownloadProvenanceAgent"
    output_files = ("downloaded_artifact.json", "provenance.json")

    def run(self) -> AgentContext:
        candidate_id = self.context.data.get("candidate_id")
        if not candidate_id:
            payload = {
                "schema_version": "1.0",
                "status": "not_executed",
                "reason": "No candidate_id was provided to DownloadProvenanceAgent.",
            }
        else:
            payload = download_candidate(str(candidate_id), out=self.context.cache_dir / "downloads")
        self.write_json("downloaded_artifact.json", payload)
        self.write_json("provenance.json", payload)
        self.context.data["downloaded_artifact"] = payload
        return self.context
