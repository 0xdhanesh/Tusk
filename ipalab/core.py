"""IPA Lab non-UI workflow primitives. Thread-safe callbacks; no prompting or printing."""
from __future__ import annotations

import copy
import json
import os
import plistlib
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable
from zipfile import ZipFile, is_zipfile

FAIRPLAY_URL = "https://github.com/EthanArbuckle/fairplay-decrypt.git"
BREW_TOOLS = {"ipatool": "ipatool", "libimobiledevice": "idevice_id", "libusbmuxd": "iproxy", "ldid": "ldid"}
MAX_ZIP_MEMBERS = 50000
MAX_EXTRACTED_BYTES = 10 * 1024**3
COPY_BUFSIZE = 1024 * 1024
Log = Callable[[str], None]

class WorkflowError(Exception):
    """An actionable error the user can resolve and retry."""


def available_tools() -> tuple[list[str], list[str]]:
    missing_brew = [formula for formula, tool in BREW_TOOLS.items() if not shutil.which(tool)]
    missing_other = [tool for tool in ("ssh", "ssh-keygen", "otool", "git", "make", "xcrun", "brew") if not shutil.which(tool)]
    return missing_brew, missing_other


def free_port(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def next_free_port(start: int, stop: int = 2500) -> int:
    for port in range(max(start, 1024), min(stop, 65535) + 1):
        if free_port(port):
            return port
    raise WorkflowError(f"No free TCP port found between {start} and {stop}.")


def safe_ipa_path(raw: str) -> Path:
    path = Path(raw.strip()).expanduser().absolute()
    if not raw.strip() or path.suffix.lower() != ".ipa":
        raise WorkflowError("Choose a full path ending in .ipa.")
    return path


def unique_ipa_path(path: Path) -> Path:
    if not path.exists() and not path.is_symlink():
        return path
    for n in range(2, 10000):
        candidate = path.with_name(f"{path.stem}-{n}{path.suffix}")
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise WorkflowError("Unable to find an unused IPA filename.")


def parse_search(raw: str) -> list[dict]:
    """ipatool can return an array, dict, or JSON log line in either stream."""
    parsed = []
    for text in [raw.strip(), *raw.splitlines()]:
        if not text:
            continue
        try:
            parsed.append(json.loads(text))
        except ValueError:
            pass
    if not parsed:
        decoder = json.JSONDecoder()
        for match in re.finditer(r"[\[{]", raw):
            try:
                obj, _ = decoder.raw_decode(raw[match.start():])
                parsed.append(obj)
                break
            except ValueError:
                continue
    for obj in reversed(parsed):
        if isinstance(obj, list):
            return [a for a in obj if isinstance(a, dict)]
        if isinstance(obj, dict):
            for key in ("apps", "results", "data"):
                if isinstance(obj.get(key), list):
                    return [a for a in obj[key] if isinstance(a, dict)]
    return []


def bundle_id(app: dict) -> str:
    return str(app.get("bundleID") or app.get("bundleId") or app.get("bundleIdentifier") or "")


def parse_otool(raw: str) -> list[tuple[int, int]]:
    found = []
    for match in re.finditer(r"\bcmd\s+LC_ENCRYPTION_INFO(?:_64)?\b(.*?)(?=\nLoad command|\Z)", raw, re.S):
        section = match.group(1)
        cryptid = re.search(r"\bcryptid\s+(\d+)", section)
        size = re.search(r"\bcryptsize\s+(\d+)", section)
        if cryptid:
            found.append((int(cryptid.group(1)), int(size.group(1)) if size else 0))
    return found


def is_macho(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    with path.open("rb") as inp:
        return inp.read(4) in {
            b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
            b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        }


def validate_zip(path: Path) -> None:
    if not path.is_file() or not path.stat().st_size or not is_zipfile(path):
        raise WorkflowError(f"Not a valid IPA/ZIP archive: {path}")


def guarded_members(archive: ZipFile) -> None:
    members = archive.infolist()
    if len(members) > MAX_ZIP_MEMBERS:
        raise WorkflowError("Unusually high number of IPA entries. Stopped for safety.")
    if len(set(a.filename for a in members)) != len(members):
        raise WorkflowError("IPA has duplicate ZIP entries.")
    if sum(a.file_size for a in members) > MAX_EXTRACTED_BYTES:
        raise WorkflowError("Uncompressed IPA exceeds 10 GiB safety limit.")
    for member in members:
        name = member.filename
        if not name or name.startswith("/") or "\\" in name or ".." in PurePosixPath(name).parts:
            raise WorkflowError(f"Unsafe IPA entry: {name!r}")
        mode = (member.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise WorkflowError(f"Unsafe symlink in archive: {name!r}")


@dataclass
class Inspection:
    app_rel: str
    executable: str
    bundle: str
    min_ios: str
    binaries: list[tuple[str, int | None, int | None]]

    @property
    def encrypted(self) -> bool:
        return any(c is not None and c != 0 for _, c, _ in self.binaries)

    @property
    def unknown(self) -> bool:
        return any(c is None for _, c, _ in self.binaries)


class CommandRunner:
    """Stream non-interactive external tools; only kill processes started by this instance."""

    def __init__(self, log: Log):
        self.log = log
        self._active: set[subprocess.Popen] = set()
        self._lock = threading.Lock()
        self.cancelled = threading.Event()

    def run(self, argv: list[str], *, cwd: Path | None = None, timeout: float = 900,
            checked: bool = True, capture_full: bool = False,
            log_output: bool = True) -> tuple[int, str]:
        if self.cancelled.is_set():
            raise WorkflowError("Operation was cancelled.")
        self.log("$ " + shlex.join([str(a) for a in argv]))
        try:
            proc = subprocess.Popen(
                argv, cwd=str(cwd) if cwd else None, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding="utf-8", errors="replace", bufsize=1,
                start_new_session=True,
            )
        except OSError as exc:
            raise WorkflowError(f"Unable to execute {argv[0]}: {exc}") from exc
        with self._lock:
            self._active.add(proc)
        lines: deque[str] = deque(maxlen=180)
        all_lines: list[str] | None = [] if capture_full else None
        try:
            assert proc.stdout is not None
            # Separate collector prevents read starvation on long-running tasks.
            def collector() -> None:
                for line in proc.stdout:
                    text = line.rstrip("\r\n")
                    lines.append(text)
                    if all_lines is not None:
                        all_lines.append(text)
                    if log_output:
                        self.log(text)
            watcher = threading.Thread(target=collector, name="ipa-command-output", daemon=True)
            watcher.start()
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._stop(proc)
                raise WorkflowError(f"Timed out after {int(timeout)}s: {argv[0]}")
            watcher.join(timeout=3)
            tail = "\n".join(lines)
            if checked and returncode:
                raise WorkflowError(f"{Path(argv[0]).name} failed (exit {returncode}).\n" + tail[-1800:])
            return returncode, "\n".join(all_lines) if all_lines is not None else tail
        finally:
            if proc.poll() is None:
                self._stop(proc)
            with self._lock:
                self._active.discard(proc)

    @staticmethod
    def _stop(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass

    def stop_all(self) -> None:
        self.cancelled.set()
        with self._lock:
            processes = list(self._active)
        for proc in processes:
            self._stop(proc)


class USBTunnel:
    """Manage iproxy as a subprocess, never as a blocking SSH thread."""

    def __init__(self, udid: str, port: int, log: Log):
        self.udid, self.port, self.log = udid, port, log
        self.proc: subprocess.Popen | None = None
        self.reader: threading.Thread | None = None

    def start(self) -> None:
        if not free_port(self.port):
            raise WorkflowError(f"Local TCP port {self.port} is already in use.")
        cmd = ["iproxy", "-l", "-u", self.udid, f"{self.port}:22"]
        self.log("$ " + shlex.join(cmd))
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1, start_new_session=True)
        def read() -> None:
            assert self.proc is not None and self.proc.stdout is not None
            for line in self.proc.stdout:
                self.log("iproxy: " + line.rstrip())
        self.reader = threading.Thread(target=read, daemon=True, name="iproxy-output")
        self.reader.start()
        time.sleep(0.35)
        if self.proc.poll() is not None:
            raise WorkflowError(f"iproxy exited with status {self.proc.returncode}; check the activity panel.")

    def stop(self) -> None:
        if self.proc:
            CommandRunner._stop(self.proc)
        if self.reader:
            self.reader.join(timeout=2)


def enumerate_usb(runner: CommandRunner) -> list[str]:
    _, out = runner.run(["idevice_id"], timeout=25)
    devices = []
    for line in out.splitlines():
        parts = line.split()
        if parts and (len(parts) == 1 or parts[1] == "(USB)") and re.fullmatch(r"[A-Za-z0-9-]{12,80}", parts[0]):
            devices.append(parts[0])
    return list(dict.fromkeys(devices))


def ssh_cmd(port: int, user: str = "root", batch: bool = True, tty: bool = False) -> list[str]:
    cmd = ["ssh", "-o", f"BatchMode={'yes' if batch else 'no'}",
           "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=8", "-o", "NumberOfPasswordPrompts=3"]
    if tty:
        cmd += ["-tt"]
    return [*cmd, "-p", str(port), f"{user}@127.0.0.1"]


def test_root_ssh(port: int, runner: CommandRunner) -> bool:
    code, out = runner.run(ssh_cmd(port) + ["id -u"], checked=False, timeout=20)
    return code == 0 and out.strip().splitlines()[-1:] == ["0"]


def public_key_path() -> Path:
    return Path.home() / ".ssh" / "id_ed25519.pub"


def root_key_command(public_key: str) -> str:
    safe = shlex.quote(public_key)
    return ('umask 077; mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; '
            'touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; '
            f'grep -Fqx {safe} "$HOME/.ssh/authorized_keys" || '
            f'printf "%s\\n" {safe} >> "$HOME/.ssh/authorized_keys"')


def inspect_ipa(path: Path, dest: Path, runner: CommandRunner, log: Log) -> Inspection:
    validate_zip(path)
    with ZipFile(path) as zip_file:
        guarded_members(zip_file)
        zip_file.extractall(dest)
    payload = dest / "Payload"
    apps = sorted(p for p in payload.glob("*.app") if p.is_dir())
    if len(apps) != 1:
        raise WorkflowError("Expected exactly one top-level Payload/*.app bundle.")
    app = apps[0]
    plist = app / "Info.plist"
    if not plist.is_file():
        raise WorkflowError("IPA main Info.plist is missing.")
    with plist.open("rb") as f:
        metadata = plistlib.load(f)
    executable = metadata.get("CFBundleExecutable")
    if not isinstance(executable, str) or not (app / executable).is_file():
        raise WorkflowError("Invalid or missing CFBundleExecutable.")
    binaries = []
    for file in sorted(payload.rglob("*")):
        if not is_macho(file):
            continue
        relative = str(file.relative_to(dest))
        result, raw = runner.run(["otool", "-l", str(file)], checked=False, timeout=90,
                                 capture_full=True, log_output=False)
        if result:
            binaries.append((relative, None, None))
            log(f"Unable to determine encryption: {relative}")
            continue
        parsed = parse_otool(raw)
        cryptid = max((c for c, _ in parsed), default=0)
        cryptsize = sum(s for _, s in parsed)
        binaries.append((relative, cryptid, cryptsize))
        if cryptid:
            log(f"Encrypted • cryptid={cryptid} • {cryptsize:,} bytes • {relative}")
    return Inspection(str(app.relative_to(dest)), executable,
                      str(metadata.get("CFBundleIdentifier", "unknown")),
                      str(metadata.get("MinimumOSVersion", "not specified")), binaries)


def set_min_ios(source: Path, target: Path, app_rel: str) -> None:
    member_name = app_rel + "/Info.plist"
    with ZipFile(source) as original, ZipFile(target, "x") as updated:
        guarded_members(original)
        if member_name not in original.namelist():
            raise WorkflowError("Info.plist missing from final IPA.")
        updated.comment = original.comment
        for member in original.infolist():
            info = copy.copy(member)
            if member.filename == member_name:
                metadata = plistlib.loads(original.read(member))
                metadata["MinimumOSVersion"] = "15.0"  # intentionally fixed target
                updated.writestr(info, plistlib.dumps(metadata, fmt=plistlib.FMT_BINARY))
            else:
                with original.open(member, "r") as src, updated.open(info, "w") as dst:
                    shutil.copyfileobj(src, dst, length=COPY_BUFSIZE)


def exclusive_verified_copy(source: Path, target: Path) -> None:
    """Compatible with APFS and exFAT; refuse overwrite and remove partial files."""
    made = False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as inp, target.open("xb") as out:
            made = True
            shutil.copyfileobj(inp, out, length=COPY_BUFSIZE)
            out.flush()
            os.fsync(out.fileno())
        with ZipFile(target) as z:
            failed = z.testzip()
            if failed:
                raise WorkflowError(f"Invalid CRC in output: {failed}")
    except BaseException:
        if made:
            target.unlink(missing_ok=True)
        raise


def prepare_fairplay(repo: Path, runner: CommandRunner) -> Path:
    if not (repo / "decrypt.py").is_file() or not (repo / "credential-retrieval" / "retrieve.py").is_file():
        raise WorkflowError(f"Not a fairplay-decrypt checkout: {repo}")
    python = repo / "venv" / "bin" / "python3"
    if not python.is_file():
        runner.run([sys.executable, "-m", "venv", str(repo / "venv")], timeout=180)
    code, _ = runner.run([str(python), "-c", "import cryptography; assert int(cryptography.__version__.split('.')[0]) >= 41"],
                         checked=False, timeout=20)
    if code:
        runner.run([str(python), "-m", "pip", "install", "-r", str(repo / "requirements.txt")], cwd=repo, timeout=700)
    bundle = repo / "credential-retrieval" / "build" / "bundle" / "credential.ios"
    if not bundle.is_file():
        runner.run(["xcrun", "--sdk", "iphoneos", "--find", "clang"], timeout=30)
        runner.run(["make"], cwd=repo, timeout=650)
    if not bundle.is_file():
        raise WorkflowError("Build completed but credential.ios is still missing.")
    return python


def retrieve_credential(repo: Path, python: Path, ipa: Path, port: int, temp: Path, runner: CommandRunner) -> Path:
    output = temp / "credentials"
    if output.exists():
        shutil.rmtree(output)
    help_code, help_text = runner.run([str(python), "credential-retrieval/retrieve.py", "--help"], cwd=repo,
                                      timeout=30, checked=False, capture_full=True, log_output=False)
    command = [str(python), "credential-retrieval/retrieve.py", "--ssh-port", str(port),
               "--output-dir", str(output)]
    if "--ipa" in help_text and help_code == 0:
        command += ["--ipa", str(ipa)]
    else:
        runner.log("This fairplay-decrypt checkout has no --ipa flag; ensure the matching App Store account/app is on the device.")
    runner.run(command, cwd=repo, timeout=400)
    credential = output / "credential.bin"
    if not credential.is_file() or credential.stat().st_size != 16:
        raise WorkflowError("FairPlay retrieval did not produce a 16-byte credential.bin.")
    credential.chmod(0o600)
    return credential


def decrypt_ipa(repo: Path, python: Path, ipa: Path, credential: Path, temp: Path, runner: CommandRunner) -> Path:
    target = temp / "decrypted-working.ipa"
    target.unlink(missing_ok=True)
    # The isolated temp folder is on macOS' native volume, avoiding hard-link problems on exFAT.
    runner.run([str(python), "decrypt.py", str(ipa), str(target), "--credential", str(credential)],
               cwd=repo, timeout=1100)
    validate_zip(target)
    return target
