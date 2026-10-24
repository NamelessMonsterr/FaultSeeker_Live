"""Static build/launch contracts; these checks do not execute installs or Docker."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_static_surface_matches_generated_server_sources():
    for path, content in load_tool("sync_static").outputs().items():
        assert path.read_bytes() == content, str(path)


def test_local_launchers_use_single_verified_pipeline_pin():
    pin = load_tool("pipeline_pin").read_pin()
    assert len(pin) == 40
    for name in ("run.sh", "run.bat"):
        value = (ROOT / name).read_text()
        assert "tools/pipeline_pin.py" in value.replace("\\", "/")
        assert "checkout --detach" in value and "rev-parse HEAD" in value
        assert "console-demo-compat" not in value


def test_cache_seed_matches_pipeline_working_directory():
    docker = (ROOT / "Dockerfile").read_text()
    assert "WORKDIR /srv" in docker
    assert "cp api/capture /srv/data/cache/forensics/" in docker
    assert "/srv/FaultSeeker-/data/cache" not in docker
    for name in ("run.sh", "run.bat"):
        assert "FaultSeeker-/data/cache" not in (ROOT / name).read_text().replace("\\", "/")


def test_container_declares_nonroot_user_and_app_transport_dependencies():
    docker = (ROOT / "Dockerfile").read_text()
    assert "USER faultseeker" in docker and "chown -R faultseeker:faultseeker /srv" in docker
    requirements = (ROOT / "app/requirements-app.txt").read_text()
    assert "openai==2.36.0" in requirements and "httpx==0.28.1" in requirements
