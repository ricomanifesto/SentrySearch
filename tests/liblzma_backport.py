"""Explicit, offline final-image checks for the liblzma backport.

Run through dev/check_service_images.py, not default test discovery. Both image
references must already exist locally. POSIX /tmp is used only to stage the
test-tools image's /probe directory for a readonly mount into each candidate.
No fixtures or test binaries are required in the release image itself.

The allocation-failure cases cover alone and auto's alone-format dispatch;
they do not claim direct lzip/MicroLZMA coverage or sanitizer instrumentation.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import uuid

import pytest


def docker(*args: str, check: bool = True, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f"docker {args[0]} exited {result.returncode}: {result.stderr}")
    return result


def local_image(variable: str) -> str:
    reference = os.environ.get(variable)
    if not reference:
        pytest.fail(f"Set {variable} to an already-built local image")
    image_id = docker("image", "inspect", "--format", "{{.Id}}", reference).stdout.strip()
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), image_id
    # Pin once so a retag during the suite cannot change the tested bytes.
    return image_id


@pytest.fixture(scope="module")
def search_image() -> str:
    return local_image("SENTRYSEARCH_TEST_IMAGE")


@contextmanager
def owned_container(*arguments: str) -> Iterator[str]:
    name = f"search-liblzma-{uuid.uuid4().hex}"
    try:
        docker("create", "--pull=never", "--name", name, *arguments)
        yield name
    finally:
        # The name is owned before create, including timeout/partial-create cases.
        result = docker("rm", "--force", name, check=False, timeout=20)
        if result.returncode and "No such container" not in result.stderr:
            raise AssertionError(f"Could not remove owned container {name}: {result.stderr}")


@pytest.fixture(scope="module")
def probe_directory() -> Iterator[Path]:
    tools_image = local_image("SENTRYSEARCH_LIBLZMA_TEST_IMAGE")
    with tempfile.TemporaryDirectory(prefix="search-liblzma-", dir="/tmp") as temporary:
        directory = Path(temporary) / "probe"
        # The scratch tools image is never started, and no command need exist in it.
        with owned_container(
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--entrypoint",
            "/not-executed",
            tools_image,
        ) as source:
            docker("cp", f"{source}:/probe", str(directory))
        assert {path.name for path in directory.iterdir()} == {
            "decoder_reinit_test",
            "good-unknown_size-with_eopm.lzma",
        }
        for path in directory.iterdir():
            assert path.is_file() and not path.is_symlink(), path.name
        assert os.access(directory / "decoder_reinit_test", os.X_OK)
        yield directory


def in_candidate(
    image: str, *command: str, probe: Path | None = None
) -> subprocess.CompletedProcess[str]:
    arguments = [
        "--network=none",
        "--read-only",
        "--user=10001:10001",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=256m",
        "--memory-swap=256m",
        "--pids-limit=32",
        "--ulimit=core=0",
    ]
    if probe is not None:
        arguments += ["--mount", f"type=bind,src={probe},dst=/probe,readonly"]
    with owned_container(*arguments, image, *command) as name:
        result = docker("start", "--attach", name, check=False)
        state = json.loads(docker("inspect", "--format", "{{json .State}}", name).stdout)
        assert not state["Running"], "Attached test returned while container was still running"
        assert not state["OOMKilled"], "Container OOM is not controlled allocator-failure evidence"
        return result


@pytest.mark.parametrize("mode", ["alone", "auto"])
def test_decoder_recovers_after_injected_allocation_failure(
    search_image: str, probe_directory: Path, mode: str
):
    result = in_candidate(
        search_image,
        "/probe/decoder_reinit_test",
        mode,
        "/probe/good-unknown_size-with_eopm.lzma",
        probe=probe_directory,
    )
    output = result.stdout + result.stderr
    assert f"mode={mode} " in output, output
    assert "small-before: result=1 written=13" in output, output
    assert "large-rejected: result=5 written=0" in output, output  # LZMA_MEM_ERROR
    assert re.search(r"injected_rejections=[1-9][0-9]*\b", output), output
    assert result.returncode == 0, output
    assert "small-after: result=1 written=13" in output, output
    balance = re.search(r"allocations=([0-9]+) frees=([0-9]+) live=0 result=PASS\b", output)
    assert balance and int(balance[1]) > 0 and balance[1] == balance[2], output


PYTHON_PREAMBLE = """
import io
import lzma
from contextlib import contextmanager

payload = bytes(range(256)) * 8

@contextmanager
def raises(expected):
    try:
        yield
    except expected:
        pass
    else:
        raise AssertionError('Expected ' + expected.__name__)
"""

PYTHON_CASES = {
    "raw_round_trip": """
        filters = [{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 20}]
        compressed = lzma.compress(payload, format=lzma.FORMAT_RAW, filters=filters)
        assert lzma.decompress(compressed, format=lzma.FORMAT_RAW, filters=filters) == payload
    """,
    "xz_and_alone_round_trip": """
        for format_ in (lzma.FORMAT_XZ, lzma.FORMAT_ALONE):
            stream = lzma.compress(payload, format=format_)
            assert lzma.decompress(stream) == payload
    """,
    "concatenated_streams": """
        for format_ in (lzma.FORMAT_XZ, lzma.FORMAT_ALONE):
            stream = lzma.compress(payload, format=format_)
            assert lzma.decompress(stream + stream) == payload * 2
    """,
    "forward_backward_seek": """
        data = lzma.compress(payload) + lzma.compress(payload)
        with lzma.LZMAFile(io.BytesIO(data)) as handle:
            assert handle.read(17) == payload[:17]
            assert handle.seek(len(payload) + 8) == len(payload) + 8
            assert handle.read(11) == payload[8:19]
            assert handle.seek(0) == 0
            assert handle.read() == payload * 2
        assert handle.closed
    """,
    "incremental_decode": """
        decoder = lzma.LZMADecompressor()
        result = decoder.decompress(lzma.compress(payload), max_length=31)
        for _ in range(100):
            if decoder.eof:
                break
            assert not decoder.needs_input
            result += decoder.decompress(b'', max_length=31)
        assert decoder.eof and result == payload
        with raises(EOFError):
            decoder.decompress(b'')
    """,
    "invalid_truncated_and_memlimit": """
        with raises(lzma.LZMAError):
            lzma.decompress(b'not a compressed stream')
        with raises(lzma.LZMAError):
            lzma.decompress(lzma.compress(payload)[:-12])
        # This checks compatibility, not the allocator-failure regression above.
        with raises(lzma.LZMAError):
            lzma.decompress(lzma.compress(payload), memlimit=1024)
    """,
    "explicit_decoder_reinitialization": """
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        stream = lzma.compress(payload, format=lzma.FORMAT_ALONE)
        decoder.__init__(format=lzma.FORMAT_ALONE)
        assert decoder.decompress(stream) == payload
        # CPython preserves its own EOF flag when __init__ is called again after
        # completion. This pins existing wrapper behavior, not allocation failure.
        decoder.__init__(format=lzma.FORMAT_ALONE)
        with raises(EOFError):
            decoder.decompress(stream)
    """,
}


@pytest.mark.parametrize("case", list(PYTHON_CASES))
def test_python_lzma_compatibility(search_image: str, case: str):
    script = PYTHON_PREAMBLE + textwrap.dedent(PYTHON_CASES[case])
    result = in_candidate(search_image, "python", "-c", script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_release_keeps_honest_backport_metadata(search_image: str):
    expected = json.loads(
        (Path(__file__).resolve().parents[1] / "container/liblzma/manifest.json").read_text()
    )
    script = """
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
import _lzma

root = Path('/var/lib/dpkg/status.d')
status = (root / 'liblzma5').read_text()
expected = json.loads(sys.argv[1])
architecture = {'aarch64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
assert '\\nVersion: ' + expected['patched_version'] + '\\n' in '\\n' + status
assert '\\nArchitecture: ' + architecture + '\\n' in '\\n' + status
assert '\\nSource: xz-utils\\n' in '\\n' + status
manifest = json.loads(Path('/usr/share/sentrysearch/liblzma-backport.json').read_text())
assert set(manifest) == set(expected) | {'architecture', 'package_sha256', 'library_sha256'}
assert {key: manifest[key] for key in expected} == expected
assert manifest['architecture'] == architecture
assert re.fullmatch('[0-9a-f]{64}', manifest['package_sha256'])
assert re.fullmatch('[0-9a-f]{64}', manifest['library_sha256'])
checked = []
for line in (root / 'liblzma5.md5sums').read_text().splitlines():
    digest, relative = line.split(maxsplit=1)
    path = Path('/') / relative
    assert path.is_file(), relative
    assert hashlib.md5(path.read_bytes()).hexdigest() == digest, relative
    checked.append(path)
library = Path('/usr/lib/aarch64-linux-gnu/liblzma.so.5').resolve()
if architecture == 'amd64':
    library = Path('/usr/lib/x86_64-linux-gnu/liblzma.so.5').resolve()
assert library in checked
assert hashlib.sha256(library.read_bytes()).hexdigest() == manifest['library_sha256']
assert Path('/usr/share/doc/liblzma5/copyright') in checked
assert str(library) in Path('/proc/self/maps').read_text()
assert not Path('/probe').exists(), 'Test fixtures must not ship in the release image'
assert _lzma.__file__.startswith('/usr/local/lib/python3.11/')
print('Package provenance, checksums and normal Python linkage verified')
"""
    result = in_candidate(search_image, "python", "-c", script, json.dumps(expected))
    assert result.returncode == 0, result.stdout + result.stderr
