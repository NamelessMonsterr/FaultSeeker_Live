"""Static layout/launch contracts for the unified repository. Nothing here installs or runs Docker."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]   # <repo>/console
REPO = ROOT.parent                            # <repo>
SEED = "0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb"


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_static_surface_matches_generated_server_sources():
    for path, content in load_tool("sync_static").outputs().items():
        assert path.read_bytes() == content, str(path)


def test_repository_contains_pipeline_console_and_original_material():
    assert (REPO / "faultseeker" / "main.py").is_file()
    assert (REPO / "faultseeker" / "utils" / "rpc_provider.py").is_file()
    assert (REPO / "console" / "app" / "server.py").is_file()
    assert (REPO / "console" / "app" / "web" / "index.html").is_file()
    assert (REPO / "LICENSE").is_file()
    assert (REPO / "full_paper").is_dir()
    assert (REPO / "docs" / "original" / "README.original.md").is_file()


def test_server_defaults_to_the_repository_root_pipeline():
    source = (ROOT / "app" / "server.py").read_text(encoding="utf-8")
    assert 'PROJECT_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))' in source
    assert 'REPO = os.environ.get("FAULTSEEKER_REPO", PROJECT_ROOT)' in source
    assert "load_env_file(" in source


def test_launchers_start_console_from_this_repo_without_cloning():
    sh = (REPO / "run.sh").read_text()
    bat = (REPO / "run.bat").read_text().replace("\\", "/")
    for text in (sh, bat):
        assert "console/app/server.py" in text
        assert "console/app/requirements-app.txt" in text
        assert "DEMO_GATE_PASSWORD" in text
        assert "git clone" not in text and "FaultSeeker-" not in text
        assert "FAULTSEEKER_REPO" in text
        assert SEED in text


def test_container_builds_from_repository_and_runs_nonroot():
    docker = (REPO / "Dockerfile").read_text()
    assert "WORKDIR /srv" in docker
    assert "COPY faultseeker faultseeker" in docker
    assert "COPY console/app console/app" in docker
    assert "cp console/api/capture /srv/data/cache/forensics/" in docker
    assert "git clone" not in docker
    assert "USER faultseeker" in docker and "chown -R faultseeker:faultseeker /srv" in docker
    assert 'CMD ["python", "console/app/server.py"]' in docker


def test_transport_dependencies_are_pinned():
    requirements = (ROOT / "app" / "requirements-app.txt").read_text()
    assert "openai==2.36.0" in requirements and "httpx==0.28.1" in requirements


def test_env_template_contains_no_secrets_and_is_the_only_tracked_env_file():
    template = (REPO / ".env.example").read_text().splitlines()
    assert any(line.startswith("DEMO_GATE_PASSWORD=") for line in template)
    for line in template:
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.endswith(("_API_KEY", "_RPC_URL")):
            assert value == "", key
    ignore = (REPO / ".gitignore").read_text()
    assert ".env\n" in ignore and "!.env.example" in ignore


def test_root_pytest_collects_only_pipeline_tests():
    config = (REPO / "pytest.ini").read_text()
    assert "testpaths = tests" in config and "console" in config
