from __future__ import annotations

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.agents.documentation import build_documentation_context
from apk_docforge.renderers.codex_prompt import render_codex_prompt
from apk_docforge.renderers.markdown import write_markdown


class CodexPromptBuilderAgent(BaseAgent):
    name = "CodexPromptBuilderAgent"
    output_files = ("codex_ingestion_prompt.md", "codex_context.json")

    def run(self) -> AgentContext:
        data = build_documentation_context(self.context)
        prompt = render_codex_prompt(data)
        write_markdown(self.path("codex_ingestion_prompt.md"), prompt)
        self.write_json("codex_context.json", data)
        self.context.data["codex_context"] = data
        return self.context
