"""Disposable TLS fixtures for local tests, never deployment trust material."""

from dataclasses import dataclass
from pathlib import Path
import subprocess


@dataclass(frozen=True)
class Certificates:
    ca: Path
    certificate: Path
    key: Path


def create_certificates(
    directory: Path, *, hostname: str = "localhost", expired: bool = False
) -> Certificates:
    directory.mkdir(parents=True, exist_ok=True)
    fixture = Certificates(
        directory / "ca.pem", directory / "server.pem", directory / "server-key.pem"
    )

    def openssl(*args: str) -> None:
        subprocess.run(
            ["openssl", *args], cwd=directory, check=True, capture_output=True, timeout=15
        )

    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca-key.pem",
        "-out",
        "ca.pem",
        "-days",
        "1",
        "-subj",
        "/CN=Disposable Test CA",
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "server-key.pem",
        "-out",
        "server.csr",
        "-subj",
        "/CN=Disposable Test Server",
    )
    (directory / "authority.cnf").write_text(
        "[ca]\ndefault_ca=fixture\n[fixture]\ndatabase=index.txt\nserial=serial.txt\n"
        "new_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca-key.pem\n"
        "default_md=sha256\ndefault_days=1\npolicy=subject\nx509_extensions=server\n"
        "[subject]\ncommonName=supplied\n[server]\nbasicConstraints=CA:FALSE\n"
        f"subjectAltName=DNS:{hostname}"
        + (",IP:127.0.0.1" if hostname == "localhost" else "")
        + "\nextendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    (directory / "index.txt").write_text("", encoding="utf-8")
    (directory / "serial.txt").write_text("02\n", encoding="utf-8")
    openssl(
        "ca",
        "-batch",
        "-notext",
        "-config",
        "authority.cnf",
        "-in",
        "server.csr",
        "-out",
        "server.pem",
        *(["-startdate", "20200101000000Z", "-enddate", "20200102000000Z"] if expired else []),
    )
    return fixture
