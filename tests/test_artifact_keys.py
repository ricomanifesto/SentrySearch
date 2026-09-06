from typing import Any, cast

from src.storage.s3_manager import S3StorageManager


def test_different_content_never_overwrites_a_published_object():
    objects: dict[str, bytes] = {}

    class Client:
        def put_object(self, **kwargs):
            objects[kwargs["Key"]] = kwargs["Body"]

    store = S3StorageManager()
    store.s3_client = cast(Any, Client())
    store._initialized = True
    first = store.upload_markdown_report("report-1", "winner")
    second = store.upload_markdown_report("report-1", "late writer")
    assert first is not None and second is not None
    assert first != second
    assert objects[first] == b"winner"
    assert store.upload_markdown_report("report-1", "winner") == first
    trace_a = store.upload_trace_data("report-1", {"attempt": 1})
    trace_b = store.upload_trace_data("report-1", {"attempt": 2})
    assert trace_a is not None and trace_b is not None
    assert trace_a != trace_b
    assert b'"attempt": 1' in objects[trace_a]
