import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Anchor ke direktori repo, BUKAN relative ke CWD: hasil scan dulu
# nempel di shell directory user (python /path/verd.py dari ~/Downloads
# -> ~/Downloads/outputs/) sehingga outputs/ di repo selalu menampilkan
# scan pertama saja — "scan kedua tidak ada di outputs".
OUTPUT_DIR = str(Path(__file__).resolve().parent.parent / "outputs")


def sanitize_filename(name: str) -> str:
    """Sanitize target name for use as filename — prevent path traversal."""
    sanitized = re.sub(r'[^\w\.\-]', '_', name)
    sanitized = sanitized.strip('._')
    return sanitized or 'unnamed'


@dataclass
class ProjectState:
    """Serializable scan state for save/resume."""
    target: str = ""
    seed_url: str = ""
    mode: str = ""
    version: str = ""
    subs: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    scan_urls: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    params: dict = field(default_factory=dict)
    target_wafs: list[str] = field(default_factory=list)
    auth_tokens: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    local_storage: dict = field(default_factory=dict)
    t0: float = 0.0
    phase_done_surface: bool = False
    phase_done_recon: bool = False
    phase_done_app: bool = False
    phase_done_assault: bool = False

    def save(self) -> str:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe_name = sanitize_filename(self.target)
        path = os.path.join(OUTPUT_DIR, f"{safe_name}.state")
        # Atomic write: write to temp file, then rename
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2, default=str)
        os.replace(tmp_path, path)
        return path

    @staticmethod
    def load(path: str) -> "ProjectState":
        with open(path, "r") as f:
            data = json.load(f)
        return ProjectState(**{k: v for k, v in data.items()
                               if k in ProjectState.__dataclass_fields__})

