from __future__ import annotations

import pytest

from apk_docforge.services.analysis_store import AnalysisNotFoundError, locate_analysis


def test_locate_analysis_rejects_unsafe_lookup_characters(isolated_app_env) -> None:
    with pytest.raises(AnalysisNotFoundError, match="unsupported characters"):
        locate_analysis("../outside")

    with pytest.raises(AnalysisNotFoundError, match="unsupported characters"):
        locate_analysis("*")
