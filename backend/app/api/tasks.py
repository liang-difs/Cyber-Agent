"""Task management API — track Celery async tasks."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form

from app.api.deps import get_current_user, scoped_tenant
from app.rbac.permissions import Permission, require_permission

router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])

PCAP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "pcap")
MAX_PCAP_SIZE = 2 * 1024 * 1024 * 1024  # 2GB
SYNC_PCAP_MAX_SIZE = 500 * 1024 * 1024  # Sync fallback limit; files above this require Celery workers.
PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


@router.get("/{task_id}")
async def get_task_status(
    task_id: str,
    user: dict = Depends(_get_current_user),
):
    """Get status of an async task."""
    try:
        from app.tasks.celery_app import celery_app
        result = celery_app.AsyncResult(task_id)
        return {
            "task_id": task_id,
            "status": result.status,
            "result": result.result if result.ready() else None,
            "traceback": result.traceback if result.failed() else None,
        }
    except Exception:
        return {
            "task_id": task_id,
            "status": "UNKNOWN",
            "result": None,
            "traceback": None,
            "warning": "Celery broker not available",
        }


@router.post("/alert-triage")
async def submit_alert_triage(
    alert_id: str,
    rule_id: str,
    description: str = "",
    src_ip: Optional[str] = None,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_TRIAGE, auth=Depends(_get_current_user))),
):
    """Submit an alert for triage (P0 priority). Falls back to sync if no Celery workers."""
    tenant_id = scoped_tenant(user)

    # Check if Celery workers are available
    use_sync = True
    try:
        from app.tasks.celery_app import celery_app
        inspector = celery_app.control.inspect(timeout=1.0)
        active = inspector.active()
        if active:
            use_sync = False
    except Exception:
        pass

    if use_sync:
        import logging
        logger = logging.getLogger(__name__)
        logger.info("No Celery workers, running alert triage synchronously")
        try:
            from app.tasks.alert_triage import triage_alert
            result = triage_alert(
                alert_id=alert_id,
                rule_id=rule_id,
                description=description,
                src_ip=src_ip,
                tenant_id=tenant_id,
            )
            return {"task_id": "sync-" + alert_id[:12], "status": "completed", "queue": "sync", "result": result}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        try:
            from app.tasks.alert_triage import triage_alert
            result = triage_alert.delay(
                alert_id=alert_id,
                rule_id=rule_id,
                description=description,
                src_ip=src_ip,
                tenant_id=tenant_id,
            )
            return {"task_id": result.id, "status": "submitted", "queue": "celery_critical"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


@router.post("/pcap-analysis")
async def submit_pcap_analysis(
    pcap_path: str,
    max_packets: int = 10000,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.TASK_SUBMIT, auth=Depends(_get_current_user))),
):
    """Submit a pcap file for analysis (P1 priority)."""
    tenant_id = scoped_tenant(user)
    try:
        from app.tasks.pcap_analysis import analyze_pcap
        result = analyze_pcap.delay(
            pcap_path=pcap_path,
            tenant_id=tenant_id,
            max_packets=max_packets,
        )
        return {"task_id": result.id, "status": "submitted", "queue": "celery_high"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/upload-file")
async def upload_file(
    file: UploadFile = File(...),
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.TASK_SUBMIT, auth=Depends(_get_current_user))),
):
    """Upload a file and return its server path (no analysis).

    Used by the Agent chat to upload pcap files for tool-based analysis.
    """
    filename = file.filename or "upload.dat"
    ext = os.path.splitext(filename)[1].lower()
    tenant_id = scoped_tenant(user)

    # Save to disk
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "uploads", tenant_id)
    os.makedirs(upload_dir, exist_ok=True)
    save_name = f"{uuid.uuid4().hex}{ext}"
    save_path = os.path.join(upload_dir, save_name)

    total_size = 0
    with open(save_path, "wb") as f:
        while True:
            chunk = await file.read(8192)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > MAX_PCAP_SIZE:
                os.remove(save_path)
                raise HTTPException(status_code=413, detail="File too large (max 2GB)")
            f.write(chunk)

    return {
        "file_path": save_path,
        "filename": filename,
        "size_bytes": total_size,
    }


@router.post("/pcap-upload")
async def upload_pcap(
    file: UploadFile = File(...),
    max_packets: int = Form(default=10000),
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.TASK_SUBMIT, auth=Depends(_get_current_user))),
):
    """Upload a pcap file for analysis (P1 priority).

    Accepts multipart/form-data with a .pcap or .pcapng file.
    Validates magic bytes, saves to disk, submits Celery task.
    """
    # Validate file extension
    filename = file.filename or "upload.pcap"
    ext = os.path.splitext(filename)[1].lower()
    tenant_id = scoped_tenant(user)
    if ext not in (".pcap", ".pcapng"):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are accepted")

    # Read and validate magic bytes
    header = await file.read(4)
    if header not in (PCAP_MAGIC, PCAPNG_MAGIC):
        raise HTTPException(status_code=400, detail="Invalid pcap file (magic bytes mismatch)")
    await file.seek(0)

    # Save to disk
    os.makedirs(os.path.join(PCAP_DIR, tenant_id), exist_ok=True)
    save_name = f"{uuid.uuid4().hex}{ext}"
    save_path = os.path.join(PCAP_DIR, tenant_id, save_name)

    total_size = 0
    with open(save_path, "wb") as f:
        while True:
            chunk = await file.read(8192)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > MAX_PCAP_SIZE:
                os.remove(save_path)
                raise HTTPException(status_code=413, detail="File too large (max 2GB)")
            f.write(chunk)

    # Check if Celery workers are available, otherwise run synchronously
    use_sync = True
    try:
        from app.tasks.celery_app import celery_app
        inspector = celery_app.control.inspect(timeout=1.0)
        active = inspector.active()
        if active:
            use_sync = False
    except Exception:
        pass

    if use_sync:
        import logging
        logger = logging.getLogger(__name__)
        if total_size > SYNC_PCAP_MAX_SIZE:
            raise HTTPException(
                status_code=503,
                detail="PCAP analysis worker unavailable; large files require Celery workers",
            )
        logger.info("No Celery workers, running pcap analysis synchronously")
        try:
            from app.tasks.pcap_analysis import analyze_pcap
            analysis_result = analyze_pcap(
                pcap_path=save_path,
                tenant_id=tenant_id,
                max_packets=max_packets,
                display_filename=filename,
            )
            return {
                "task_id": "sync-" + uuid.uuid4().hex[:12],
                "status": "completed",
                "queue": "sync",
                "filename": filename,
                "size_bytes": total_size,
                "sync": True,
                "result": analysis_result,
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        try:
            from app.tasks.pcap_analysis import analyze_pcap
            result = analyze_pcap.delay(
                pcap_path=save_path,
                tenant_id=tenant_id,
                max_packets=max_packets,
                display_filename=filename,
            )
            return {
                "task_id": result.id,
                "status": "submitted",
                "queue": "celery_high",
                "filename": filename,
                "size_bytes": total_size,
                "sync": False,
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


@router.get("/pcap-files")
async def list_pcap_files(
    user: dict = Depends(_get_current_user),
):
    """List uploaded PCAP files for the current tenant."""
    tenant_id = scoped_tenant(user)
    tenant_dir = os.path.join(PCAP_DIR, tenant_id)
    if not os.path.isdir(tenant_dir):
        return {"files": [], "total_size_bytes": 0}

    files = []
    total_size = 0
    for name in sorted(os.listdir(tenant_dir), reverse=True):
        path = os.path.join(tenant_dir, name)
        if not os.path.isfile(path):
            continue
        stat = os.stat(path)
        files.append({
            "filename": name,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
        })
        total_size += stat.st_size

    return {"files": files, "total_size_bytes": total_size}
