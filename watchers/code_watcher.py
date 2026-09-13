"""
Security Watchtower — Code Watcher
Monitors source code files for security anti-patterns using:
  1. File system watching (watchdog) — react to changes in real time
  2. AST-based static analysis (Python files)
  3. Regex-based pattern scanning (all supported languages)

Emits structured Finding events to the Redis findings queue.
"""

from __future__ import annotations

import ast
import hashlib
import logging
import os
import re
import stat
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Generator, List, Optional, Tuple

from .config import settings
from .redis_client import push_finding, store_finding_record
from .schema import (
    Finding, FindingSource, FindingType, Severity,
    new_finding,
)

logger = logging.getLogger("watchtower.code_watcher")
MAX_FILE_SIZE_BYTES = 1024 * 1024

# ─── Security Patterns ────────────────────────────────────────────────────────  # noqa: E501
# Each entry: (regex_pattern, finding_type, severity, title_template, confidence)

SECURITY_PATTERNS: List[Tuple[re.Pattern, str, str, str, float]] = [
    # Secrets / credentials
    (re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key|private[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{16,})["\']'),  # noqa: E501
     FindingType.HARDCODED_SECRET.value, Severity.CRITICAL.value, "Hardcoded API/Secret Key detected", 0.90),
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']'),
     FindingType.HARDCODED_SECRET.value, Severity.CRITICAL.value, "Hardcoded Password detected", 0.85),
    (re.compile(r'(?i)(access_token|auth_token|bearer)\s*[=:]\s*["\']([A-Za-z0-9._\-]{20,})["\']'),
     FindingType.HARDCODED_SECRET.value, Severity.CRITICAL.value, "Hardcoded Auth Token detected", 0.88),
    (re.compile(r'-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'),
     FindingType.HARDCODED_SECRET.value, Severity.CRITICAL.value, "Private Key material found in source", 0.99),  # noqa: E501
    (re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}'),
     FindingType.HARDCODED_SECRET.value, Severity.CRITICAL.value, "GitHub Personal Access Token detected", 0.97),  # noqa: E501
    (re.compile(r'sk-[A-Za-z0-9]{48}'),
     FindingType.HARDCODED_SECRET.value, Severity.CRITICAL.value, "OpenAI API Key detected", 0.97),

    # SQL Injection risk
    (re.compile(r'(?i)(execute|cursor\.execute|db\.query|\.raw\()\s*\(\s*["\'].*%\s*["\']|f["\'].*{.*}.*SELECT|f["\'].*{.*}.*WHERE'),  # noqa: E501
     FindingType.SQL_INJECTION_RISK.value, Severity.HIGH.value, "Potential SQL injection: f-string or % in query", 0.75),  # noqa: E501
    (re.compile(r'(?i)["\']\s*SELECT.+FROM.+WHERE.+["\'] \+'),
     FindingType.SQL_INJECTION_RISK.value, Severity.HIGH.value, "SQL string concatenation detected", 0.80),

    # Dangerous eval/exec
    (re.compile(r'\b(eval|exec)\s*\('),
     FindingType.EVAL_USAGE.value, Severity.HIGH.value, "eval()/exec() usage detected — potential code injection", 0.80),  # noqa: E501

    # SSRF indicators
    (re.compile(r'(?i)(requests\.get|requests\.post|urllib\.request|httpx\.get|aiohttp\.get)\s*\([^)]*\+'),
     FindingType.SSRF_RISK.value, Severity.HIGH.value, "Potential SSRF: HTTP client called with concatenated URL", 0.65),  # noqa: E501

    # Weak crypto
    (re.compile(r'(?i)\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)\('),
     FindingType.WEAK_CRYPTO.value, Severity.MEDIUM.value, "Weak hash algorithm (MD5/SHA1) detected", 0.88),
    (re.compile(r'(?i)des\.new|DES\.encrypt|ECB'),
     FindingType.WEAK_CRYPTO.value, Severity.HIGH.value, "Weak encryption algorithm (DES/ECB) detected", 0.85),  # noqa: E501

    # Mass assignment / open models
    (re.compile(r'__fields__\s*=\s*["\']__all__["\']|fields\s*=\s*["\']__all__["\']'),
     FindingType.MASS_ASSIGNMENT.value, Severity.HIGH.value, "Mass assignment risk: __all__ field exposure", 0.80),  # noqa: E501

    # Open redirect
    (re.compile(r'(?i)redirect\s*\(\s*request\.(GET|POST|args)\['),
     FindingType.OPEN_REDIRECT.value, Severity.HIGH.value, "Potential open redirect via unvalidated user input", 0.72),  # noqa: E501

    # Missing auth decorators (Django/Flask/FastAPI)
    (re.compile(r'@app\.route\([^)]+\)\s*\ndef\s+\w+\([^)]*\)\s*:\s*\n(?!\s*@login_required)'),
     FindingType.MISSING_AUTH_CHECK.value, Severity.MEDIUM.value, "Route handler potentially missing auth decorator", 0.55),  # noqa: E501

    # Reentrancy / state-before-call (Solidity detection)
    (re.compile(r'\.transfer\(|\.send\(|\.call\{'),
     FindingType.REENTRANCY_RISK.value, Severity.CRITICAL.value, "Solidity external call detected — verify CEI pattern", 0.70),  # noqa: E501
]


# ─── File Hashing (Change Detection) ─────────────────────────────────────────

_file_hashes: "OrderedDict[str, str]" = OrderedDict()
_file_hashes_lock = threading.Lock()
MAX_TRACKED_FILES = 100_000


def _read_file_snapshot(path: str) -> tuple[bytes, os.stat_result]:
    """Read one bounded regular-file snapshot without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os,
        "O_NOFOLLOW",
        0,
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("scan target is not a regular file")
        if before.st_size > MAX_FILE_SIZE_BYTES:
            raise OSError("scan target exceeds the file-size limit")

        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_FILE_SIZE_BYTES + 1 - bytes_read),
            )
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > MAX_FILE_SIZE_BYTES:
                raise OSError("scan target grew beyond the file-size limit")

        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if before_identity != after_identity or bytes_read != after.st_size:
            raise OSError("scan target changed while it was being read")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _file_hash(path: str) -> str:
    content, _ = _read_file_snapshot(path)
    return hashlib.sha256(content).hexdigest()


def _has_changed(path: str) -> bool:
    try:
        current = _file_hash(path)
        with _file_hashes_lock:
            if _file_hashes.get(path) == current:
                _file_hashes.move_to_end(path)
                return False
            _file_hashes[path] = current
            _file_hashes.move_to_end(path)
            while len(_file_hashes) > MAX_TRACKED_FILES:
                _file_hashes.popitem(last=False)
            return True
    except OSError:
        return False


# ─── Regex Scanner ────────────────────────────────────────────────────────────

def _scan_file_regex(
    path: str,
    source: str,
) -> Generator[Finding, None, None]:
    """Scan a file using regex security patterns. Yields findings."""
    for lineno, line in enumerate(source.splitlines(keepends=True), start=1):
        # Skip comment lines (best-effort)
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--")):
            continue

        for pattern, finding_type, severity, title, confidence in SECURITY_PATTERNS:
            if (
                finding_type == FindingType.HARDCODED_SECRET.value
                and not settings.code_watcher.secret_patterns_enabled
            ):
                continue
            if pattern.search(line):
                service, system = _infer_service_system(path)
                line_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
                logger.warning(
                    "Pattern match | type=%s severity=%s file=%s line=%d",
                    finding_type, severity, path, lineno
                )
                yield new_finding(
                    source=FindingSource.CODE.value,
                    type=finding_type,
                    severity=severity,
                    service=service,
                    system=system,
                    title=f"{title} [{Path(path).name}:{lineno}]",
                    description=f"Security pattern matched in {path} at line {lineno}",
                    file=path,
                    line=lineno,
                    confidence=confidence,
                    context={
                        "pattern_type": finding_type,
                        "file_path": path,
                        "line_sha256": line_hash,
                        "evidence": "[REDACTED]",
                    },
                )
                break  # One finding per line per file (avoid noise)


# ─── AST-Based Python Analyzer ────────────────────────────────────────────────

class _ASTVisitor(ast.NodeVisitor):
    """Walk a Python AST and flag dangerous patterns."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: List[Finding] = []

    def _emit(self, node: ast.AST, finding_type: str, severity: str,
              title: str, desc: str, confidence: float) -> None:
        lineno = getattr(node, "lineno", None)
        service, system = _infer_service_system(self.filepath)
        self.findings.append(new_finding(
            source=FindingSource.CODE.value,
            type=finding_type,
            severity=severity,
            service=service,
            system=system,
            title=f"{title} [{Path(self.filepath).name}:{lineno}]",
            description=desc,
            file=self.filepath,
            line=lineno,
            confidence=confidence,
            context={"ast_node": type(node).__name__},
        ))

    def visit_Call(self, node: ast.Call) -> None:
        # eval() / exec()
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self._emit(
                node, FindingType.EVAL_USAGE.value, Severity.HIGH.value,
                "eval()/exec() call detected",
                "Direct use of eval()/exec() can execute arbitrary code.",
                0.88
            )
        # subprocess with shell=True
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "call", "Popen"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._emit(
                        node, FindingType.SUSPICIOUS_PATTERN.value, Severity.HIGH.value,
                        "subprocess shell=True detected",
                        "shell=True allows shell injection via unsanitized input.",
                        0.85
                    )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Dangerous null dereference: x.y without None check (heuristic)
        if isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Attribute):
            # Chained attribute access x.y.z — possible NPE
            # Only flag if it looks like user.something.something_sensitive
            if hasattr(node.value, "attr") and node.value.attr in ("password", "token", "secret", "key"):
                self._emit(
                    node, FindingType.NULL_DEREFERENCE.value, Severity.MEDIUM.value,
                    "Possible null dereference on sensitive field",
                    f"Attribute chain on sensitive field '{node.value.attr}' without None guard.",
                    0.55
                )
        self.generic_visit(node)


def _scan_file_ast(path: str, source: str) -> List[Finding]:
    """AST scan for Python files only."""
    if not path.endswith(".py"):
        return []
    try:
        tree = ast.parse(source, filename=path)
        visitor = _ASTVisitor(path)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        return []  # Not parseable — skip, don't crash
    except Exception as exc:
        logger.debug("AST scan failed for %s: %s", path, exc)
        return []


# ─── Service/System Inference ─────────────────────────────────────────────────

def _infer_service_system(path: str) -> Tuple[str, str]:
    """Infer a repository service/component without unrelated domain mappings."""
    parts = Path(path).parts
    for marker in ("services", "components"):
        try:
            marker_index = parts.index(marker)
        except ValueError:
            continue
        if marker_index + 1 < len(parts):
            candidate = parts[marker_index + 1].strip()
            if candidate:
                return candidate[:200], settings.platform

    parent = Path(path).parent.name.strip()
    return (parent or "unknown-service")[:200], settings.platform


# ─── Emit Helper ─────────────────────────────────────────────────────────────

def _emit_finding(finding: Finding) -> None:
    payload = finding.to_json()
    push_finding(payload)
    store_finding_record(finding.id, payload)
    logger.info(
        "Code finding emitted | id=%s severity=%s type=%s file=%s line=%s",
        finding.id[:8], finding.severity, finding.type, finding.file, finding.line
    )


# ─── Full File Scan ───────────────────────────────────────────────────────────

def scan_file(path: str) -> List[Finding]:
    """Scan a single file. Returns list of findings."""
    try:
        raw_source, _ = _read_file_snapshot(path)
    except OSError as exc:
        logger.debug(
            "Cannot snapshot scan target | file=%s error_type=%s",
            path,
            type(exc).__name__,
        )
        return []

    source = raw_source.decode("utf-8", errors="ignore")
    findings: List[Finding] = []
    try:
        findings.extend(_scan_file_regex(path, source))
        findings.extend(_scan_file_ast(path, source))
    except Exception as exc:
        logger.error(
            "File scan failed | file=%s error_type=%s",
            path,
            type(exc).__name__,
        )
    deduplicated: list[Finding] = []
    seen: set[tuple[str, Optional[int]]] = set()
    for finding in findings:
        key = (finding.type, finding.line)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated


def _is_ignored(path: Path, ignore_names: set[str]) -> bool:
    return any(part in ignore_names for part in path.parts)


def scan_directory(root: str, *, changed_only: bool = False) -> int:
    """Recursively scan a directory. Returns count of findings emitted."""
    cfg = settings.code_watcher
    count = 0
    root_p = Path(root)
    ignore = set(cfg.ignore_paths)

    for path in root_p.rglob("*"):
        if _is_ignored(path, ignore):
            continue
        if (
            not path.is_file()
            or path.is_symlink()
            or path.suffix not in cfg.watch_extensions
        ):
            continue
        changed = _has_changed(str(path))
        if changed_only and not changed:
            continue
        findings = scan_file(str(path))
        for finding in findings:
            _emit_finding(finding)
        count += len(findings)
    return count


# ─── File System Watcher (watchdog) ──────────────────────────────────────────

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not installed — falling back to polling. Install with: pip install watchdog")


if WATCHDOG_AVAILABLE:
    class _SecurityEventHandler(FileSystemEventHandler):
        def __init__(self):
            self.cfg = settings.code_watcher
            self._failure: Optional[Exception] = None
            self._failure_lock = threading.Lock()

        def _record_failure(self, exc: Exception) -> None:
            with self._failure_lock:
                if self._failure is None:
                    self._failure = exc
            logger.error(
                "Filesystem event handling failed | error_type=%s",
                type(exc).__name__,
            )

        def raise_if_failed(self) -> None:
            with self._failure_lock:
                failure = self._failure
            if failure is not None:
                raise RuntimeError(
                    "code watcher event handling failed"
                ) from failure

        def _should_scan(self, path: str) -> bool:
            target = Path(path)
            return (
                target.suffix in self.cfg.watch_extensions
                and not target.is_symlink()
                and not _is_ignored(target, set(self.cfg.ignore_paths))
            )

        def on_modified(self, event):
            try:
                if event.is_directory:
                    return
                if not self._should_scan(event.src_path):
                    return
                if not _has_changed(event.src_path):
                    return  # Identical content — skip
                logger.info("File modified: %s", event.src_path)
                service, system = _infer_service_system(event.src_path)
                modified_finding = new_finding(
                    source=FindingSource.CODE.value,
                    type=FindingType.FILE_MODIFIED.value,
                    severity=Severity.LOW.value,
                    service=service,
                    system=system,
                    title=f"File Modified: {Path(event.src_path).name}",
                    description=f"Monitored file changed: {event.src_path}",
                    file=event.src_path,
                    confidence=1.0,
                    context={"event": "modified"},
                )
                _emit_finding(modified_finding)
                for finding in scan_file(event.src_path):
                    _emit_finding(finding)
            except Exception as exc:
                self._record_failure(exc)

        def on_created(self, event):
            try:
                if event.is_directory or not self._should_scan(event.src_path):
                    return
                logger.info("New file detected: %s", event.src_path)
                _has_changed(event.src_path)
                for finding in scan_file(event.src_path):
                    _emit_finding(finding)
            except Exception as exc:
                self._record_failure(exc)


# ─── Main Watch Loop ──────────────────────────────────────────────────────────

def watch(stop_event: Optional[threading.Event] = None) -> None:
    """
    Main code watcher entry point.
    1. Optional full scan on startup.
    2. File system watching via watchdog or polling fallback.
    """
    cfg = settings.code_watcher
    active_paths = [
        watch_path
        for watch_path in cfg.watch_paths
        if Path(watch_path).is_dir() and not Path(watch_path).is_symlink()
    ]
    if not active_paths:
        raise RuntimeError("none of the configured code watch paths is a directory")

    if cfg.scan_on_start:
        for watch_path in active_paths:
            logger.info("Initial scan of %s ...", watch_path)
            count = scan_directory(watch_path)
            logger.info("Initial scan complete | path=%s findings=%d", watch_path, count)

    if WATCHDOG_AVAILABLE:
        observer = Observer()
        handler = _SecurityEventHandler()
        for watch_path in active_paths:
            observer.schedule(handler, watch_path, recursive=True)
            logger.info("Watching (inotify): %s", watch_path)
        observer.start()
        try:
            while not (stop_event and stop_event.is_set()):
                handler.raise_if_failed()
                if not observer.is_alive():
                    raise RuntimeError("code watcher observer stopped unexpectedly")
                if stop_event:
                    stop_event.wait(1)
                else:
                    time.sleep(1)
        finally:
            observer.stop()
            observer.join(timeout=10)
            if observer.is_alive():
                raise RuntimeError("code watcher observer did not stop")
            logger.info("Code watcher stopped.")
    else:
        # Polling fallback
        logger.info("Code watcher polling fallback active (interval=60s)")
        while not (stop_event and stop_event.is_set()):
            for watch_path in active_paths:
                scan_directory(watch_path, changed_only=True)
            if stop_event:
                stop_event.wait(60)
            else:
                time.sleep(60)


# ─── Standalone Entry Point ───────────────────────────────────────────────────

if __name__ == "__main__":
    settings.validate()
    watch()
