#!/usr/bin/env python3
"""Single command entrypoint for IPA Lab Desktop on macOS.

Bootstraps PySide6 into a project-local .venv with explicit user approval.
Prefers Python 3.13 on systems whose default python3 is too new for Qt wheels.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"


def ask(question: str) -> bool:
    try:
        answer = input(question + " [y/N]: ").strip().casefold()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def supported_python(path: str) -> bool:
    try:
        output = subprocess.run([path, "-c", "import sys;print(sys.version_info.major,sys.version_info.minor)"],
                                capture_output=True, text=True, timeout=12)
        if output.returncode:
            return False
        major, minor = map(int, output.stdout.strip().split())
        return major == 3 and 10 <= minor <= 13
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def chosen_python() -> str:
    if supported_python(sys.executable):
        return sys.executable
    # The macOS system Python 3.15 seen in some setups may lack a PySide6 wheel.
    names = ("python3.13", "python3.12", "python3.11", "python3.10")
    for name in names:
        path = shutil.which(name)
        if path and supported_python(path):
            return path
    for prefix in ("/opt/homebrew/bin", "/usr/local/bin"):
        for name in names:
            path = str(Path(prefix) / name)
            if Path(path).is_file() and supported_python(path):
                return path
    if not shutil.which("brew"):
        raise RuntimeError("No compatible Python found. Install Homebrew Python 3.13 and try again.")
    print("IPA Lab needs Python 3.10–3.13 for this Qt build.")
    if not ask("Allow IPA Lab to install python@3.13 through Homebrew?"):
        raise RuntimeError("Python 3.13 setup declined; no packages were installed.")
    outcome = subprocess.run(["brew", "install", "python@3.13"], check=False)
    if outcome.returncode:
        raise RuntimeError("Homebrew Python 3.13 installation failed.")
    for path in ("/opt/homebrew/bin/python3.13", "/usr/local/bin/python3.13", shutil.which("python3.13")):
        if path and supported_python(path):
            return path
    raise RuntimeError("Python 3.13 was installed but its executable was not found. Check brew --prefix python@3.13.")


def bootstrap() -> None:
    if importlib.util.find_spec("PySide6") is not None:
        return
    python = VENV / "bin" / "python3"
    if not python.exists():
        print("IPA Lab Desktop needs PySide6 (Qt). It will be installed in a project-local .venv.")
        if not ask("Create .venv and install the graphical interface dependency?"):
            raise RuntimeError("UI dependency installation was declined.")
        source = chosen_python()
        print("Creating local Python environment…")
        subprocess.run([source, "-m", "venv", str(VENV)], check=True)
    if Path(sys.executable).resolve() != python.resolve():
        os.execv(str(python), [str(python), str(Path(__file__).resolve()), *sys.argv[1:]])
    # Running inside project's .venv.
    if not ask("Install/update PySide6 in this .venv (no system Python changes)?"):
        raise RuntimeError("PySide6 is required to start the desktop application.")
    subprocess.run([str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")], check=True)
    if importlib.util.find_spec("PySide6") is None:
        # importlib caches may need invalidation after pip install.
        importlib.invalidate_caches()
    if importlib.util.find_spec("PySide6") is None:
        raise RuntimeError("PySide6 installation did not produce an importable module.")


def main() -> int:
    parser = argparse.ArgumentParser(description="IPA Lab — Impactor-inspired macOS IPA research desktop")
    parser.add_argument("--local-ipa", type=Path, help="open an existing IPA immediately")
    parser.add_argument("--fairplay-repo", type=Path, help="use an existing fairplay-decrypt checkout")
    parser.add_argument("--port", type=int, default=2222, help="preferred localhost iproxy port")
    parser.add_argument("--demo", action="store_true", help="non-operational UI preview (for development)")
    args = parser.parse_args()
    if platform.system() != "Darwin" and not args.demo:
        print("IPA Lab requires macOS. No commands were run.", file=sys.stderr)
        return 2
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    try:
        bootstrap()
        from ipalab.desktop import launch
        return launch(local_ipa=args.local_ipa, fairplay_repo=args.fairplay_repo,
                      port=args.port, demo=args.demo)
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print("IPA Lab: " + str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
