"""
Image upload and file serving routes.
"""

import logging
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.security import get_current_user
from app.schemas.schemas import MessageResponse, UploadResponse
from app.services.ai_modules.anti_scraping import BotDetector

router = APIRouter()
logger = logging.getLogger(__name__)
_bot_detector = BotDetector()


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload an image for protection",
)
async def upload_image(
    request: Request,
    file: UploadFile = File(..., description="Image file (JPG, PNG, WEBP, HEIC)"),
    current_user: dict = Depends(get_current_user),
):
    # Bot detection — serve differently handled in processing route
    ua = request.headers.get("user-agent", "")
    is_bot, confidence, reason = _bot_detector.analyse(ua, dict(request.headers))
    if is_bot:
        logger.warning("Bot upload attempt: %s (confidence=%.0f%%, reason=%s)", ua, confidence * 100, reason)

    # Validate content type
    if file.content_type not in settings.ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.content_type}. Allowed: {settings.ALLOWED_IMAGE_TYPES}",
        )

    # Read and validate size
    image_bytes = await file.read()
    if len(image_bytes) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {settings.MAX_UPLOAD_SIZE_MB} MB",
        )

    # Quick magic-byte check (verify it's actually an image)
    _validate_image_magic(image_bytes, file.content_type)

    # Save to upload directory
    job_id = str(uuid.uuid4()).replace("-", "")[:24]
    ext = Path(file.filename or "image.jpg").suffix.lower() or ".jpg"
    save_path = os.path.join(settings.UPLOAD_DIR, f"{job_id}_input{ext}")
    Path(save_path).write_bytes(image_bytes)

    logger.info(
        "Image uploaded: job_id=%s size=%d bytes type=%s user=%s",
        job_id, len(image_bytes), file.content_type, current_user.get("sub", "anon"),
    )

    return UploadResponse(
        job_id=job_id,
        filename=file.filename or "upload",
        size_bytes=len(image_bytes),
        mime_type=file.content_type,
    )


@router.get(
    "/output/{filename}",
    summary="Download a protected output image",
    response_class=FileResponse,
)
async def get_output_image(
    filename: str,
    current_user: dict = Depends(get_current_user),
):
    # Sanitise filename (prevent path traversal)
    safe_name = Path(filename).name
    file_path = os.path.join(settings.OUTPUT_DIR, safe_name)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Output file not found")

    return FileResponse(
        path=file_path,
        media_type="image/png",
        filename=safe_name,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@router.get(
    "/input/{job_id}",
    summary="Retrieve the original uploaded image",
    response_class=FileResponse,
)
async def get_input_image(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    upload_dir = Path(settings.UPLOAD_DIR)
    matches = list(upload_dir.glob(f"{job_id}_input*"))
    if not matches:
        raise HTTPException(status_code=404, detail="Input file not found")

    file_path = str(matches[0])
    suffix = matches[0].suffix.lower()
    mime_map = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}
    media_type = mime_map.get(suffix, "image/jpeg")

    return FileResponse(path=file_path, media_type=media_type)


@router.delete(
    "/{job_id}",
    response_model=MessageResponse,
    summary="Delete job files (GDPR right to erasure)",
)
async def delete_job_files(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    deleted = 0
    for directory in [settings.UPLOAD_DIR, settings.OUTPUT_DIR]:
        for f in Path(directory).glob(f"{job_id}*"):
            f.unlink(missing_ok=True)
            deleted += 1

    if deleted == 0:
        raise HTTPException(status_code=404, detail="No files found for this job ID")

    logger.info("Files deleted for job %s by user %s", job_id, current_user.get("sub"))
    return MessageResponse(message=f"Deleted {deleted} file(s) for job {job_id}")


# ── Helpers ───────────────────────────────────────────────────────────────

def _validate_image_magic(data: bytes, claimed_type: str) -> None:
    """Verify magic bytes match the claimed MIME type."""
    MAGIC = {
        "image/jpeg": [b"\xff\xd8\xff"],
        "image/png":  [b"\x89PNG"],
        "image/webp": [b"RIFF"],
        "image/heic": [b"ftyp"],
    }
    signatures = MAGIC.get(claimed_type, [])
    for sig in signatures:
        if data[:len(sig)] == sig:
            return
    if signatures:  # Only hard-fail for types we know
        raise HTTPException(
            status_code=400,
            detail="File content does not match declared content type (possible spoofing)",
        )
