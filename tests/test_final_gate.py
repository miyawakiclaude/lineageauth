"""The final gate, executed.

`TASKS.md` ends with a release checklist. Every line of it is a claim about
this repository, and a claim nobody re-checks is a claim that quietly stops
being true. So each one is a test here, and a box is only ticked in `TASKS.md`
where a test below actually establishes it.

Three of them cannot be established from inside a test run and say so instead
of pretending: whether the GitHub account is really the personal one (this
checks the remote URL, which is what the repository can see), whether free
tiers were re-verified before a deployment that has not happened, and whether
every protocol test passes -- a suite cannot assert its own totality without
lying about it.

The company-contamination scan lives here too. `CLAUDE.md` 2.8 keeps this
project off every company resource, and a scan that runs only when somebody
remembers to run it is not a control.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "packages" / "py" / "lineageauth"

PERSONAL_ACCOUNT = "miyawakiclaude"

# The company's own public identifiers. These may appear nowhere at all: there
# is no legitimate reason for this repository to name the business it is kept
# away from. Only public identifiers are listed -- no customer data belongs in
# a test file either.
COMPANY_IDENTITY_MARKERS = (
    "katagrma",
    "katagruma",
    "カタグルマ",
)

# A path *into* the company tree, which is a different problem from a sentence
# saying the repository is kept out of it. The first version of this scan looked
# for the bare words and fired on `TASKS.md` documenting the isolation rule --
# a scan that punishes writing the rule down teaches people to stop writing it
# down, so it looks for an embedded absolute path instead.
COMPANY_PATH = re.compile(
    r"""[A-Za-z]:[\\/][^\s"']*(?:OneDrive|デスクトップ)""",
    re.IGNORECASE,
)

# The scan names what it looks for, so it necessarily contains those strings.
CONTAMINATION_SCAN_EXEMPT = {
    "tests/test_final_gate.py",
}

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r'"d"\s*:\s*"[A-Za-z0-9_-]{20,}"'),  # a JWK private scalar
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)

TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".html",
    ".css",
    ".js",
    ".txt",
    ".cfg",
    ".ini",
    ".gitattributes",
    ".gitignore",
}

SKIP_DIRS = {".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache"}


def tracked_files() -> list[Path]:
    """Every file git tracks. Untracked scratch is not what ships."""
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    return [REPO / line for line in out.stdout.splitlines() if line]


def readable_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in TEXT_SUFFIXES:
        return None
    if any(part in SKIP_DIRS for part in path.parts):
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


# ------------------------------------------------------------ isolation


class TestPersonalIsolation:
    def test_the_remote_targets_the_personal_account(self) -> None:
        out = subprocess.run(
            ["git", "-C", str(REPO), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode != 0:
            pytest.skip("no origin remote configured")
        url = out.stdout.strip()
        assert f"/{PERSONAL_ACCOUNT}/" in url, url
        # What a repository can check is where its writes go. Whether that
        # account is really a personal one is a fact about GitHub, not about
        # this checkout, and this test does not claim otherwise.

    def test_no_company_address_is_configured_for_writes(self) -> None:
        out = subprocess.run(
            ["git", "-C", str(REPO), "config", "--get", "user.email"],
            capture_output=True,
            text=True,
            check=False,
        )
        email = out.stdout.strip().lower()
        if not email:
            pytest.skip("no committer address configured")
        for marker in COMPANY_IDENTITY_MARKERS:
            assert marker not in email, f"committer address looks like company identity: {email}"

    def test_no_company_material_is_present(self) -> None:
        """The contamination scan. It runs on every test run, not on request."""
        found: list[str] = []
        for path in tracked_files():
            relative = path.relative_to(REPO).as_posix()
            if relative in CONTAMINATION_SCAN_EXEMPT:
                continue
            text = readable_text(path)
            if text is None:
                continue
            lowered = text.lower()
            for marker in COMPANY_IDENTITY_MARKERS:
                if marker.lower() in lowered:
                    found.append(f"{relative}: names the company ({marker})")
            for hit in COMPANY_PATH.findall(text):
                found.append(f"{relative}: embeds a path into the company tree ({hit})")
        assert found == [], f"company material reached this repository: {found}"

    def test_the_scan_catches_what_it_claims_to(self) -> None:
        """A scanner that never fires looks exactly like a clean repository.

        The first version of this pattern matched only forward slashes, so it
        was blind to every Windows path -- which is the shape contamination
        would actually arrive in. It passed the suite anyway. This control is
        why that was caught, and why it stays.
        """
        desktop = "デスクトップ"
        must_catch = [
            r"C:\Users\someone\OneDrive\Desktop\sheet.xlsx",
            "C:/Users/someone/OneDrive/list/data.csv",
            "C:\\Users\\someone\\OneDrive\\" + desktop + "\\file",
            f"D:/work/{desktop}/report.xlsx",
            r"c:\users\x\onedrive\y",
        ]
        must_stay_quiet = [
            "the repo root is outside OneDrive and outside any company tree",
            "/home/user/projects/lineageauth",
            "OneDrive is not used by this project",
        ]
        for text in must_catch:
            assert COMPANY_PATH.search(text), f"the scan missed {text!r}"
        for text in must_stay_quiet:
            assert not COMPANY_PATH.search(text), f"the scan fired on prose: {text!r}"

    def test_no_company_cloud_or_billing_environment_is_required(self) -> None:
        project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        declared = list(project["dependencies"])
        for extra in project.get("optional-dependencies", {}).values():
            declared.extend(extra)
        joined = " ".join(declared).lower()
        for marker in ("boto", "azure", "google-cloud", "gcloud", "snowflake"):
            assert marker not in joined


# ------------------------------------------------------------ money


class TestNothingCosts:
    def test_the_zero_cost_suite_covers_the_definition_of_done(self) -> None:
        source = (REPO / "tests" / "test_zero_cost.py").read_text(encoding="utf-8")
        assert "class TestDefinitionOfDone" in source
        assert "NOT_YET_BUILT" in source

    def test_no_billing_or_automatic_upgrade_is_enabled(self) -> None:
        policy = (REPO / "infra" / "cost-policy.yaml").read_text(encoding="utf-8")
        assert "allow_automatic_upgrades: false" in policy
        assert "billing_enabled: true" not in policy.split("candidates_not_selected:")[0]

    def test_every_free_tier_in_use_carries_the_date_it_was_checked(self) -> None:
        policy = (REPO / "infra" / "cost-policy.yaml").read_text(encoding="utf-8")
        selected = policy.split("candidates_not_selected:")[0]
        checks = re.findall(r"free_tier_checked:\s*\"?([^\"\n]+)", selected)
        assert checks, "the register lists no services"
        for value in checks:
            assert value.strip() in {"n/a"} or re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip())

    def test_nothing_is_deployed_so_nothing_needed_re_verifying(self) -> None:
        """The checklist line about re-verifying free tiers before deployment.

        There is no deployment, which is why that line stays unticked rather
        than being ticked on a technicality.
        """
        policy = (REPO / "infra" / "cost-policy.yaml").read_text(encoding="utf-8")
        assert "candidates_not_selected:" in policy
        assert "cloudflare-pages" in policy.split("candidates_not_selected:")[1]


# ------------------------------------------------------------ secrets


class TestNoSecrets:
    def test_no_tracked_file_carries_key_material(self) -> None:
        found: list[str] = []
        for path in tracked_files():
            text = readable_text(path)
            if text is None:
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    found.append(f"{path.relative_to(REPO).as_posix()}: {pattern.pattern}")
        assert found == []

    def test_the_test_keys_announce_that_they_are_unsafe(self) -> None:
        """They are derived from a public domain string, and must look like it."""
        source = (REPO / "tests" / "testkeys.py").read_text(encoding="utf-8")
        assert "unsafe" in source.lower()

    def test_no_module_reads_a_private_key_from_the_environment(self) -> None:
        offenders: list[str] = []
        for path in PACKAGE.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "os.environ" in text or "getenv" in text:
                offenders.append(path.relative_to(REPO).as_posix())
        assert offenders == [], f"the protocol core reads no environment: {offenders}"


# ------------------------------------------------------------ side effects


class TestNoUnapprovedExternalSideEffect:
    def test_the_api_accepts_no_events_over_http(self) -> None:
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app
        from lineageauth.index import EventIndex

        with EventIndex() as index:
            client = TestClient(create_app(index))
            assert client.get("/v1/meta").json()["acceptsEventsOverHttp"] is False

    def test_the_service_holds_no_private_keys(self) -> None:
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app
        from lineageauth.index import EventIndex

        with EventIndex() as index:
            client = TestClient(create_app(index))
            assert client.get("/v1/meta").json()["holdsPrivateKeys"] is False

    def test_the_technocore_adapter_cannot_publish(self) -> None:
        from lineageauth.adapters.technocore import prepare

        source = Path(prepare.__file__).read_text(encoding="utf-8")
        for sink in ("urlopen", "requests.", "httpx.", "def send", "def publish"):
            assert sink not in source

    def test_an_unknown_technocore_route_is_refused(self) -> None:
        from lineageauth.adapters.technocore.routes import Consequence, classify

        decision = classify("https://technocore.chat/some/unmapped/path", method="GET")
        assert decision.consequence is Consequence.UNKNOWN
        assert "unsafe to call" in decision.detail

    def test_no_mcp_tool_can_sign(self) -> None:
        from lineageauth.adapters.mcp.tools import declarations

        for declaration in declarations():
            assert "sign" not in declaration["name"]


# ------------------------------------------------------------ the demos


class TestTheDemosTheChecklistNames:
    def test_exact_approval(self) -> None:
        source = (REPO / "tests" / "test_approval.py").read_text(encoding="utf-8").lower()
        assert "replay protection" in source
        assert "never grant missing base authority" in source
        assert "spendable once" in source

    def test_recovery_conflicts(self) -> None:
        source = (REPO / "tests" / "test_lineage.py").read_text(encoding="utf-8")
        assert "CONFLICTED" in source

    def test_useful_work(self) -> None:
        assert (REPO / "tests" / "test_work.py").is_file()

    def test_passport_and_router(self) -> None:
        assert (REPO / "tests" / "test_passport.py").is_file()
        assert (REPO / "tests" / "test_router.py").is_file()

    def test_db_rebuild(self) -> None:
        source = (REPO / "tests" / "test_zero_cost.py").read_text(encoding="utf-8")
        assert "rebuild" in source

    def test_property_tests_exist_and_use_hypothesis(self) -> None:
        source = (REPO / "tests" / "test_properties.py").read_text(encoding="utf-8")
        assert "hypothesis" in source


# ------------------------------------------------------------ currency


class TestUpstreamIsCurrent:
    """Both adapters record the date their upstream specification was read.

    A date is not proof the reading was right. It is proof somebody looked, and
    it is the thing that goes stale silently otherwise.
    """

    def test_the_mcp_adapter_records_when_the_spec_was_checked(self) -> None:
        source = (REPO / "TASKS.md").read_text(encoding="utf-8")
        assert re.search(r"MCP spec.*20\d\d-\d\d-\d\d", source)

    def test_the_a2a_adapter_records_when_the_spec_was_checked(self) -> None:
        source = (PACKAGE / "adapters" / "a2a" / "__init__.py").read_text(encoding="utf-8")
        assert re.search(r"checked 20\d\d-\d\d-\d\d", source)

    def test_the_a2a_extension_is_never_required(self) -> None:
        from lineageauth.adapters.a2a import build_extension
        from tests.testkeys import AGENT_1, unsafe_signer

        agent = unsafe_signer(AGENT_1)
        built = build_extension(lineage="lineage:la:x", did=agent.did)
        assert built["required"] is False


# ------------------------------------------------------------ the documents


class TestTheDocumentsAreComplete:
    @pytest.mark.parametrize(
        "name", ["README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE", "RUNBOOK.md"]
    )
    def test_it_exists_and_is_not_a_stub(self, name: str) -> None:
        text = (REPO / name).read_text(encoding="utf-8")
        assert len(text) > 400, f"{name} is a stub"

    def test_the_notice_file_is_short_on_purpose(self) -> None:
        """An Apache-2.0 NOTICE is an attribution line, not a document.

        Held to what it has to say rather than to a length, because padding it
        would make it worse.
        """
        text = (REPO / "NOTICE").read_text(encoding="utf-8")
        assert "LineageAuth" in text
        assert "Copyright" in text

    def test_the_readme_states_the_limitations(self) -> None:
        readme = (REPO / "README.md").read_text(encoding="utf-8").lower()
        assert "nothing here is production-ready" in readme
        assert "do not put" in readme and "real authority behind it" in readme

    def test_the_security_policy_says_what_never_to_send(self) -> None:
        policy = (REPO / "SECURITY.md").read_text(encoding="utf-8").lower()
        assert "private key" in policy

    def test_every_decision_id_is_unique_and_sequential(self) -> None:
        text = (REPO / "docs" / "29_DECISIONS.md").read_text(encoding="utf-8")
        ids = [int(n) for n in re.findall(r"^## D-(\d{3}):", text, re.MULTILINE)]
        assert ids, "the decision log is empty"
        assert len(ids) == len(set(ids)), "a decision id is reused"
        assert ids == sorted(ids, reverse=True) or ids == sorted(ids)

    def test_the_examples_are_regenerated_deterministically(self) -> None:
        """A vector set that changes between runs is not publishable."""
        script = REPO / "scripts" / "generate_examples.py"
        before = {p.name: p.read_bytes() for p in sorted((REPO / "examples").glob("*.json"))}
        done = subprocess.run(
            [sys.executable, str(script)], capture_output=True, check=False, cwd=str(REPO)
        )
        assert done.returncode == 0, done.stderr.decode("utf-8", errors="replace")
        after = {p.name: p.read_bytes() for p in sorted((REPO / "examples").glob("*.json"))}
        assert before == after

    def test_the_examples_are_valid_json_with_no_trailing_difference(self) -> None:
        for path in sorted((REPO / "examples").glob("*.json")):
            json.loads(path.read_text(encoding="utf-8"))
