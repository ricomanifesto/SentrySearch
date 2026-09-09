from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from src.api import main as api
from src.core.evidence_admissibility import (
    ContentPolicyExclusion,
    classify_research_sources,
    contains_virtual_event_promotion,
)
from src.storage.models import Report
from src.storage.report_service import ReportStorageService
from src.core.promotion_content import has_promotion_marker
from tests.test_virtual_event_promotions import OPERATIONAL_SOURCE, collection_report

CASES = json.loads((Path(__file__).parent / "fixtures/promotion-markdown.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[case["markdown"] for case in CASES])
def test_authored_content_respects_rendered_markdown_and_literal_syntax(case):
    assert contains_virtual_event_promotion(case["markdown"]) is case["blocked"]
    assert has_promotion_marker(case["markdown"], representation="markdown") is case["blocked"]


@pytest.mark.parametrize("surface", ["research", "persistence", "retained", "export"])
@pytest.mark.parametrize(
    "markdown",
    [
        "[**Virtual** Event]",
        "[[Virtual](https://security.example.org) Event]",
        "[`Virtual` Event]",
        "<script>[Virtual Event]</script>",
        "<style>[Virtual Event]</style>",
    ],
)
def test_rendered_marker_is_excluded_at_every_shared_boundary(surface, markdown):
    if surface == "research":
        source = {**deepcopy(OPERATIONAL_SOURCE), "title": markdown}
        original = deepcopy(source)
        [excluded] = classify_research_sources([source])
        assert excluded["evidencePurpose"] == "excluded_non_operational"
        assert source == original
        return
    if surface == "retained":
        row = {**collection_report("retained"), "markdown_content": markdown}
        original = deepcopy(row)
        with pytest.raises(ContentPolicyExclusion):
            api.report_response_fields(row)
        assert row == original
        return
    service = ReportStorageService.__new__(ReportStorageService)
    service.db_manager = MagicMock()
    service.s3_manager = Mock()
    if surface == "persistence":
        with pytest.raises(ContentPolicyExclusion):
            service.store_report(
                {"id": "retained", "tool_name": "Security events", "markdown_content": markdown}
            )
        service.db_manager.get_session.assert_not_called()
        service.s3_manager.upload_content.assert_not_called()
    else:
        session = service.db_manager.get_session.return_value.__enter__.return_value
        session.query.return_value.filter.return_value.first.return_value = Report(
            id="retained",
            tool_name="Security events",
            markdown_s3_key="retained.md",
        )
        service.s3_manager.download_content.return_value = markdown
        with pytest.raises(ContentPolicyExclusion):
            service.get_download_url("retained")
        service.s3_manager.get_presigned_url.assert_not_called()
        session.commit.assert_not_called()


def test_fields_and_source_records_are_never_joined_into_a_marker():
    assert not contains_virtual_event_promotion([{"title": "[**Virtual**"}, {"title": "Event]"}])


@pytest.mark.parametrize(
    "html",
    [
        "<p>[Virtual</p><p>Event]</p>",
        "<div>[Virtual</div><div>Event]</div>",
        "[Virtual<br/>Event]",
        "[Virtual<br />Event]",
    ],
)
def test_html_block_and_break_whitespace_within_one_field(html):
    assert has_promotion_marker(html, representation="html")


def test_metadata_records_remain_separate_from_narrative():
    assert not has_promotion_marker('<p>[Virtual</p><img alt="Event]">', representation="html")
    assert not has_promotion_marker('<img alt="[Virtual" title="Event]">', representation="html")


@pytest.mark.parametrize(
    "representation,value,blocked",
    [
        ("text", "[**Virtual** Event]", False),
        ("markdown", "[**Virtual** Event]", True),
        ("html", "[**Virtual** Event]", False),
        ("text", "&#91;Virtual Event&#93;", False),
        ("html", "&#91;Virtual Event&#93;", True),
        ("html", "[&lt;strong&gt;Virtual&lt;/strong&gt; Event]", False),
        ("markdown", "[<strong>Virtual</strong> Event]", False),
        ("html", "[<strong>Virtual</strong> Event]", True),
        ("authored", "[<strong>Virtual</strong> Event]", True),
    ],
)
def test_explicit_representations_are_not_reparsed_as_other_formats(representation, value, blocked):
    assert has_promotion_marker(value, representation=representation) is blocked
