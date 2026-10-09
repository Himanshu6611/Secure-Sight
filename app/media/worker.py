"""Disposable decoder process; bounded wall time and Windows job memory/CPU limits."""
import ctypes
import json
import os
# Fixed interpreter/module; no shell; untrusted bytes travel only on stdin.
import subprocess  # nosec B404
import sys
import threading
import signal
import tempfile
from pathlib import Path
from .intake import MediaError
from app.security.json_policy import strict_loads

WALL_SECONDS = 15
CPU_SECONDS = 10
OUTPUT_BYTES = 256 * 1024


def windows_job(pid):
    from ctypes import wintypes as w
    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
            ("flags", w.DWORD), ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t),
            ("active", w.DWORD), ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("schedule", w.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(x, ctypes.c_uint64) for x in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.OpenProcess.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    process = kernel.OpenProcess(0x0100 | 0x0001, False, pid)
    limits = Extended()
    limits.basic.flags = 0x2000 | 0x200 | 0x4 | 0x8
    limits.basic.job_time, limits.basic.active = int(CPU_SECONDS * 10_000_000), 3
    limits.job_memory = 1024 * 1024 * 1024
    ok = job and process and kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)) and kernel.AssignProcessToJobObject(job, process)
    if process:
        kernel.CloseHandle(process)
    if not ok:
        if job:
            kernel.CloseHandle(job)
        raise MediaError("RESOURCE_LIMIT", 503)
    return kernel, job


def run(data, artifact, language, wall_seconds=None, output_limit=None):
    document_worker = artifact.get("mime") == "--email-document"
    languages = {"pdf", "docx", "xml"} if document_worker else {"eng", "hin", "eng+hin", "ara", "chi_sim", "fra", "deu", "spa"}
    if artifact.get("mime") not in {"image/png", "image/jpeg", "image/webp", "--url", "--email", "--domain", "--email-document"} or language not in languages:
        raise MediaError("INVALID_MEDIA")
    maximum_output = output_limit or OUTPUT_BYTES
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in {
            "SYSTEMROOT", "WINDIR", "PATH", "TESSERACT_CMD", "C2PA_TRUST_ANCHORS_FILE"}}
    environment.update(OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", HF_HUB_OFFLINE="1")
    workspace = tempfile.TemporaryDirectory(prefix="securesight-analysis-")
    environment.update(TEMP=workspace.name, TMP=workspace.name, TMPDIR=workspace.name,
                       PYTHONPATH=str(Path(__file__).resolve().parents[2]))
    # Interpreter/module are fixed and both remaining arguments are allowlisted.
    try:
        process = subprocess.Popen([sys.executable, "-m", "app.media.worker", artifact["mime"], language],  # nosec B603
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment,
            cwd=workspace.name, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            start_new_session=os.name != "nt")
    except Exception:
        workspace.cleanup()
        raise MediaError("ANALYSIS_FAILED", 503) from None
    job = None
    output = bytearray()
    threads = []
    try:
        if os.name == "nt":
            job = windows_job(process.pid)
        def write_input():
            try:
                process.stdin.write(data)
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass
        def read_output():
            try:
                output.extend(process.stdout.read(maximum_output + 1))
                if len(output) > maximum_output and process.poll() is None:
                    process.kill()
            except (OSError, ValueError):
                pass
        threads = [threading.Thread(target=write_input, daemon=True), threading.Thread(target=read_output, daemon=True)]
        for thread in threads:
            thread.start()
        process.wait(timeout=wall_seconds or WALL_SECONDS)
        for thread in threads:
            thread.join(timeout=2)
        if len(output) > maximum_output or process.returncode != 0:
            raise MediaError("ANALYSIS_FAILED", 422)
        result = strict_loads(output, max_depth=32, max_nodes=65536, max_items=8192)
        if not isinstance(result, dict):
            raise MediaError("ANALYSIS_FAILED", 422)
        if "error" in result:
            raise MediaError(result["error"])
        return result
    except subprocess.TimeoutExpired:
        raise MediaError("RESOURCE_LIMIT", 422) from None
    except (ValueError, UnicodeDecodeError) as exc:
        if isinstance(exc, MediaError):
            raise
        raise MediaError("ANALYSIS_FAILED", 422) from None
    finally:
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()
        if job:
            job[0].CloseHandle(job[1])
        process.wait(timeout=3)
        for thread in threads:
            thread.join(timeout=2)
        for stream in (process.stdin, process.stdout):
            if stream:
                stream.close()
        workspace.cleanup()


def run_linked(url, email_context, config, wall_seconds=25):
    """Reuse the full scanner in a separately killable 25-second process."""
    # Analysis uses the same scoring/config files, but no service identity, DB or Redis.
    safe_config = {"APP_ENV": "testing", "ANALYSIS_WORKER": True,
                   "SITE_URL": "http://localhost:5000", "TRUSTED_HOSTS": ["localhost"],
                   "RATELIMIT_STORAGE_URI": "memory://"}
    payload = json.dumps({"url": url, "email_context": email_context, "config": safe_config}).encode()
    return run(payload, {"mime": "--url"}, "eng", wall_seconds=min(25, max(1, int(wall_seconds))))


if __name__ == "__main__":
    if os.name != "nt":
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
    from .intake import validate, MAX_BYTES
    from .extract import process
    try:
        if sys.argv[1] == "--url":
            payload = json.loads(sys.stdin.buffer.read(8193))
            from app import create_app
            from app.services.scans import scan_url
            application = create_app(payload["config"])
            with application.app_context():
                result = scan_url(payload["url"], email_context=payload["email_context"])
        elif sys.argv[1] == "--domain":
            payload = json.loads(sys.stdin.buffer.read(8193))
            from utils.domain_intelligence import analyze_domain_intelligence
            result = analyze_domain_intelligence(payload["url"])
        elif sys.argv[1] == "--email":
            from app.email.parser import parse, MAX_EMAIL_BYTES
            from app.email.authentication import analyze as authenticate
            from app.email.nlp import analyze as analyze_body
            from app.email.attachments import inspect
            import base64
            raw = sys.stdin.buffer.read(MAX_EMAIL_BYTES + 1)
            result = parse(raw)
            result["authentication"] = authenticate(raw, result["headers"])
            result["body_analysis"] = analyze_body(result.pop("bodies"), result["headers"])
            attachments = []
            for attachment in result["attachments"]:
                metadata, content = inspect(attachment)
                if metadata["magic"] in {"PNG", "JPEG", "WEBP"}:
                    metadata["_data"] = base64.b64encode(content).decode()
                attachments.append(metadata)
            result["attachments"] = attachments
        elif sys.argv[1] == "--email-document":
            from app.email.documents import extract
            raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
            result = {"text": extract(raw, sys.argv[2]), "format": sys.argv[2]}
        else:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            artifact = validate(raw, sys.argv[1])
            result = process(raw, artifact, sys.argv[2])
    except MediaError as exc:
        result = {"error": exc.code}
    except Exception:
        from app.email.parser import EmailError
        exc = sys.exception()
        result = {"error": exc.code if isinstance(exc, EmailError) else "ANALYSIS_FAILED"}
    sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False))
