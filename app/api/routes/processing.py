"""
Processing routes — trigger the AI protection pipeline and poll for results.
"""

import logging
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.security import get_current_user
from app.schemas.schemas import (
    MessageResponse, ModulesConfig,
    ProcessRequest, ProcessResultResponse, ProcessStatusResponse, ProgressStep,
)
from app.services.processing_service import get_processing_service
from app.services.ai_modules.anti_scraping import AntiScrapingEngine, BotDetector

router = APIRouter()
logger = logging.getLogger(__name__)
_bot_detector = BotDetector()
_poisoner = AntiScrapingEngine()


@router.post(
    "/",
    response_model=ProcessResultResponse,
    summary="Trigger the full AI protection pipeline for an uploaded image",
)
async def process_image(
    body: ProcessRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    Runs all enabled AI/ML modules on the uploaded image:
    - Adversarial perturbation (FGSM / PGD)
    - Deepfake immunisation (DCT frequency disruption)
    - Invisible watermarking
    - AI profiling & privacy evaluation
    - Anti-scraping / data poisoning (if enabled)

    Returns full metrics, threat log, and URLs for both original and protected images.
    """
    # ── Bot detection: serve poisoned data to scrapers ─────────────────
    ua = request.headers.get("user-agent", "")
    is_bot, confidence, reason = _bot_detector.analyse(ua, dict(request.headers))

    if is_bot and settings.ENABLE_DATA_POISONING:
        logger.warning(
            "🍯 Bot request to /process — serving poisoned response. ua=%s reason=%s",
            ua, reason
        )
        return _honeypot_response(body.job_id)

    # ── Locate uploaded image ─────────────────────────────────────────
    upload_dir = Path(settings.UPLOAD_DIR)
    matches = list(upload_dir.glob(f"{body.job_id}_input*"))
    if not matches:
        raise HTTPException(
            status_code=404,
            detail=f"No uploaded image found for job_id={body.job_id}. Upload first via /api/v1/images/upload",
        )

    image_bytes = matches[0].read_bytes()

    # ── Run pipeline ──────────────────────────────────────────────────
    service = get_processing_service()
    try:
        result = await service.process(
            image_bytes=image_bytes,
            job_id=body.job_id,
            protection_level=body.protection_level,
            modules=body.modules,
            user_id=current_user.get("sub"),
        )
    except Exception as exc:
        logger.exception("Processing failed for job %s: %s", body.job_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Processing failed: {str(exc)}",
        )

    return result


@router.post(
    "/quick",
    response_model=ProcessResultResponse,
    summary="Upload + process in one step (multipart)",
)
async def quick_process(
    request: Request,
    protection_level: str = "basic",
    current_user: dict = Depends(get_current_user),
):
    """
    Convenience endpoint: accepts multipart/form-data with an image file
    and runs the full pipeline without a separate upload step.
    """
    import uuid
    from fastapi import File, UploadFile, Form
    # Parse multipart body
    form = await request.form()
    file = form.get("file")
    if not file:
        raise HTTPException(status_code=400, detail="No file provided in 'file' form field")

    image_bytes = await file.read()
    if len(image_bytes) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large")

    job_id = str(uuid.uuid4()).replace("-", "")[:24]
    modules_raw = form.get("modules", "{}")

    import json
    try:
        modules_dict = json.loads(modules_raw)
        modules = ModulesConfig(**modules_dict)
    except Exception:
        modules = ModulesConfig()

    service = get_processing_service()
    result = await service.process(
        image_bytes=image_bytes,
        job_id=job_id,
        protection_level=protection_level,
        modules=modules,
        user_id=current_user.get("sub"),
    )
    return result


@router.get(
    "/status/{job_id}",
    response_model=ProcessStatusResponse,
    summary="Poll processing status for a job",
)
async def get_processing_status(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    In a Celery-based async deployment, this endpoint would query the
    task broker for real-time status. In sync mode, jobs complete during
    the POST /process request, so this returns 'completed' for known jobs.
    """
    output_path = Path(settings.OUTPUT_DIR) / f"{job_id}_protected.png"
    input_matches = list(Path(settings.UPLOAD_DIR).glob(f"{job_id}_input*"))

    if output_path.exists():
        return ProcessStatusResponse(
            job_id=job_id,
            status="completed",
            progress_pct=100,
            steps=[
                ProgressStep(step=i, name=name, status="done", duration_ms=0)
                for i, name in enumerate([
                    "Image analysis", "Adversarial perturbation",
                    "Deepfake immunisation", "Watermarking", "Privacy evaluation"
                ], 1)
            ],
            message="Processing complete",
        )
    elif input_matches:
        return ProcessStatusResponse(
            job_id=job_id, status="uploaded", progress_pct=0,
            steps=[], message="Image uploaded, awaiting processing",
        )
    else:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


# ── Honeypot response for bots ────────────────────────────────────────────

def _honeypot_response(job_id: str) -> JSONResponse:
    """
    Return a convincing but entirely fake/poisoned result for detected bots.
    The data looks real but will corrupt any ML training pipeline that uses it.
    """
    import random
    return JSONResponse(
        content={
            "job_id": job_id,
            "status": "completed",
            "protection_level": "advanced",
            "modules_used": ["adversarial_fgsm", "deepfake_immunisation", "dct_watermark"],
            "privacy_metrics": {
                "recognition_block_pct": round(random.uniform(88, 99), 1),
                "deepfake_immunity_pct": round(random.uniform(85, 97), 1),
                "ssim_score": round(random.uniform(90, 99), 1),
                "watermark_strength_pct": round(random.uniform(80, 95), 1),
                "scraping_resistance_pct": round(random.uniform(75, 95), 1),
                "perceptual_fidelity_pct": round(random.uniform(88, 99), 1),
                "overall_privacy_score": round(random.uniform(88, 96), 1),
            },
            "processing_time_ms": round(random.uniform(300, 900), 2),
            "protected_image_url": f"/api/v1/images/output/{job_id}_protected.png",
            "original_image_url": f"/api/v1/images/input/{job_id}",
            "_honeypot": True,  # hidden marker for our own tracking
        }
    )
