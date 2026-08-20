"""The edge must not start with unusable TLS material (ADR-026 §25).

The failure this guards against is specific: a TLS deployment that quietly
serves plaintext because the certificate was missing, or that starts fine and
fails at the first handshake because the key belongs to a different certificate.
Both are configurations that look healthy until someone looks closely.

Each test starts a real container with deliberately broken material and asserts
it exits. That is slower than reading the entrypoint script and much harder to
fool: a check that has been commented out still passes a text inspection.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
IMAGE = "llm-firewall-edge:dev"


def _image_exists() -> bool:
    if not shutil.which("docker"):
        return False
    probe = subprocess.run(  # noqa: S603 - fixed argv, no user input
        [shutil.which("docker") or "docker", "image", "inspect", IMAGE],
        capture_output=True,
    )
    return probe.returncode == 0


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _image_exists(),
        reason=(
            f"{IMAGE} not built. Build it with:\n"
            "  docker compose -f compose.yaml -f compose.edge.yaml build edge"
        ),
    ),
]


def _run_edge(cert_dir: Path) -> subprocess.CompletedProcess[str]:
    """Start the edge against `cert_dir` and return once it has exited.

    No `-d`: the container is run in the foreground with a name that is thrown
    away, so the exit status is the assertion rather than something to poll for.

    `--add-host` is not decoration. `proxy_pass http://firewall-api:8000` uses a
    literal hostname, which nginx resolves at *config load* — so `nginx -t` fails
    outright when the backend name does not resolve, and the container would exit
    for a reason unrelated to its TLS material. Stubbing the name keeps the
    certificate the only variable. (That startup coupling is real and is recorded
    in ADR-026: the edge needs its backend to resolve before it will start.)
    """
    name = f"edge-tls-test-{uuid.uuid4().hex[:8]}"
    docker = shutil.which("docker") or "docker"
    try:
        return subprocess.run(  # noqa: S603 - fixed argv; paths are test-created
            [
                docker,
                "run",
                "--rm",
                "--name",
                name,
                "--network",
                "none",
                "--add-host",
                "firewall-api:127.0.0.1",
                "-e",
                "EDGE_TLS_MODE=on",
                "-v",
                f"{cert_dir}:/etc/nginx/tls:ro",
                IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        subprocess.run([docker, "rm", "-f", name], capture_output=True)  # noqa: S603


def _valid_pair(into: Path) -> None:
    subprocess.run(  # noqa: S603 - fixed argv
        [
            shutil.which("openssl") or "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "2",
            "-nodes",
            "-keyout",
            str(into / "privkey.pem"),
            "-out",
            str(into / "fullchain.pem"),
            "-subj",
            "/CN=DEVELOPMENT ONLY - tls failure-mode test",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        capture_output=True,
        check=True,
    )


@pytest.fixture
def cert_dir():
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        # World-readable: the container in these tests has default capabilities,
        # but the mode is irrelevant to what is being asserted and 0644 avoids a
        # permission failure masquerading as a validation failure.
        yield directory
        for item in directory.iterdir():
            item.chmod(0o644)


def test_a_missing_certificate_stops_the_container(cert_dir):
    result = _run_edge(cert_dir)
    assert result.returncode != 0
    assert "certificate not found" in result.stderr
    assert "must not fall back to plaintext" in result.stderr


def test_a_missing_private_key_stops_the_container(cert_dir):
    _valid_pair(cert_dir)
    (cert_dir / "privkey.pem").unlink()
    result = _run_edge(cert_dir)
    assert result.returncode != 0
    assert "private key not found" in result.stderr


def test_a_key_from_a_different_certificate_stops_the_container(cert_dir):
    """The failure mode that would otherwise survive startup and appear at the
    first handshake — long after a deployment has been declared successful."""
    _valid_pair(cert_dir)
    with tempfile.TemporaryDirectory() as other_raw:
        other = Path(other_raw)
        _valid_pair(other)
        (cert_dir / "privkey.pem").write_bytes((other / "privkey.pem").read_bytes())
        (cert_dir / "privkey.pem").chmod(0o644)
        result = _run_edge(cert_dir)

    assert result.returncode != 0
    assert "does not match the certificate" in result.stderr


def test_a_corrupt_certificate_stops_the_container(cert_dir):
    _valid_pair(cert_dir)
    (cert_dir / "fullchain.pem").write_text("-----BEGIN CERTIFICATE-----\nnot base64\n")
    result = _run_edge(cert_dir)
    assert result.returncode != 0
    assert "not a PEM certificate" in result.stderr


def test_a_valid_pair_starts(cert_dir):
    """The control. Without it every assertion above would be satisfied by a
    container that never starts for any reason at all.

    Started detached and inspected, rather than waited on: a correctly configured
    edge does not exit, so "it is still running after validation" is the property
    — and waiting for an exit that never comes would make the pass condition a
    timeout.
    """
    _valid_pair(cert_dir)
    for item in cert_dir.iterdir():
        item.chmod(0o644)

    docker = shutil.which("docker") or "docker"
    name = f"edge-tls-test-{uuid.uuid4().hex[:8]}"
    try:
        start = subprocess.run(  # noqa: S603 - fixed argv; paths are test-created
            [
                docker,
                "run",
                "-d",
                "--name",
                name,
                "--network",
                "none",
                "--add-host",
                "firewall-api:127.0.0.1",
                "-e",
                "EDGE_TLS_MODE=on",
                "-v",
                f"{cert_dir}:/etc/nginx/tls:ro",
                IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert start.returncode == 0, start.stderr

        # Long enough for the entrypoint to validate, render and run `nginx -t`.
        time.sleep(4)

        state = subprocess.run(  # noqa: S603 - fixed argv
            [docker, "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        logs = subprocess.run(  # noqa: S603 - fixed argv
            [docker, "logs", name], capture_output=True, text=True, timeout=30
        )
        output = logs.stdout + logs.stderr
    finally:
        subprocess.run([docker, "rm", "-f", name], capture_output=True)  # noqa: S603

    assert "FATAL" not in output, output
    assert "TLS is ON" in output
    assert state == "true", f"the edge exited despite valid material:\n{output}"


def test_an_unknown_mode_stops_the_container(cert_dir):
    """A typo in `EDGE_TLS_MODE` must not silently mean "off"."""
    name = f"edge-tls-test-{uuid.uuid4().hex[:8]}"
    docker = shutil.which("docker") or "docker"
    result = subprocess.run(  # noqa: S603 - fixed argv
        [
            docker,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none",
            "--add-host",
            "firewall-api:127.0.0.1",
            "-e",
            "EDGE_TLS_MODE=yes",
            IMAGE,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "EDGE_TLS_MODE must be" in result.stderr
