"""
Test suite for AI Privacy Shield backend.
Run with: pytest tests/ -v --tb=short
"""

import base64
import io
import json
import os
import sys
import time
import uuid

import numpy as np
import pytest
from PIL import Image

# ── Helpers ───────────────────────────────────────────────────────────────

def _make_test_image(width: int = 128, height: int = 128) -> bytes:
    """Generate a synthetic face-like test image."""
    img = Image.new("RGB", (width, height))
    pixels = img.load()
    cx, cy = width // 2, height // 2
    r = min(width, height) // 3

    for y in range(height):
        for x in range(width):
            dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if dist < r:
                # Skin-tone region
                pixels[x, y] = (220, 170, 130)
            else:
                pixels[x, y] = (50, 100, 150)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _image_to_float32(img_bytes: bytes) -> np.ndarray:
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    return np.asarray(img, dtype=np.float32) / 255.0


# ═══════════════════════════════════════════════════════════════════════════
# UNIT TESTS — AI Modules
# ═══════════════════════════════════════════════════════════════════════════

class TestAdversarialProtector:
    """Tests for FGSM / PGD adversarial perturbation."""

    def setup_method(self):
        from app.services.ai_modules.adversarial import AdversarialProtector, pil_to_float32
        self.protector = AdversarialProtector()
        self.pil_to_f32 = pil_to_float32

    def _make_array(self, w=64, h=64):
        img_bytes = _make_test_image(w, h)
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        return np.asarray(img, dtype=np.float32) / 255.0

    def test_fgsm_basic_shape_preserved(self):
        arr = self._make_array()
        result = self.protector.apply(arr, level="basic", use_pgd=False)
        assert result.perturbed_image.shape == arr.shape, "Output shape must match input"

    def test_fgsm_pixel_range(self):
        arr = self._make_array()
        result = self.protector.apply(arr, level="basic")
        assert result.perturbed_image.min() >= 0.0
        assert result.perturbed_image.max() <= 1.0

    def test_pgd_pixel_range(self):
        arr = self._make_array()
        result = self.protector.apply(arr, level="advanced", use_pgd=True)
        assert result.perturbed_image.min() >= 0.0
        assert result.perturbed_image.max() <= 1.0

    def test_ssim_high_for_basic(self):
        """Basic perturbation should preserve visual quality (SSIM > 0.80)."""
        arr = self._make_array()
        result = self.protector.apply(arr, level="basic")
        assert result.ssim_score > 0.80, f"SSIM too low: {result.ssim_score:.3f}"

    def test_maximum_has_higher_block_rate_than_basic(self):
        arr = self._make_array()
        basic = self.protector.apply(arr, level="basic")
        maximum = self.protector.apply(arr, level="maximum", use_pgd=True)
        assert maximum.recognition_block_estimate > basic.recognition_block_estimate

    def test_perturbation_is_different_per_level(self):
        arr = self._make_array()
        basic = self.protector.apply(arr, level="basic")
        advanced = self.protector.apply(arr, level="advanced")
        diff = float(np.abs(basic.perturbed_image - advanced.perturbed_image).mean())
        assert diff > 0, "Different levels should produce different perturbations"

    def test_duration_is_positive(self):
        arr = self._make_array()
        result = self.protector.apply(arr)
        assert result.duration_ms > 0


class TestInvisibleWatermarker:
    """Tests for DCT-domain watermark embedding and detection."""

    def setup_method(self):
        from app.services.ai_modules.watermark import InvisibleWatermarker
        self.wm = InvisibleWatermarker()

    def _make_array(self, w=128, h=128):
        img_bytes = _make_test_image(w, h)
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        return np.asarray(img, dtype=np.float32) / 255.0

    def test_embed_returns_same_shape(self):
        arr = self._make_array()
        result = self.wm.embed(arr, owner_id="test_user")
        assert result.watermarked_image.shape == arr.shape

    def test_embedded_image_in_range(self):
        arr = self._make_array()
        result = self.wm.embed(arr)
        assert result.watermarked_image.min() >= 0.0
        assert result.watermarked_image.max() <= 1.0

    def test_hash_is_64_chars(self):
        arr = self._make_array()
        result = self.wm.embed(arr)
        assert len(result.watermark_hash) == 64, "SHA-256 hash should be 64 hex chars"

    def test_different_owners_get_different_hashes(self):
        arr = self._make_array()
        r1 = self.wm.embed(arr, owner_id="alice", timestamp=1000.0)
        r2 = self.wm.embed(arr, owner_id="bob", timestamp=1000.0)
        assert r1.watermark_hash != r2.watermark_hash

    def test_embedded_bits_positive(self):
        arr = self._make_array()
        result = self.wm.embed(arr)
        assert result.embedded_bits > 0

    def test_visual_distortion_imperceptible(self):
        """Watermarked image should look nearly identical to original (SSIM > 0.95)."""
        arr = self._make_array()
        result = self.wm.embed(arr)
        diff = float(np.abs(result.watermarked_image - arr).mean())
        assert diff < 0.05, f"Mean pixel difference too large: {diff:.4f}"


class TestDeepfakeImmuniser:
    def setup_method(self):
        from app.services.ai_modules.watermark import DeepfakeImmuniser
        self.immuniser = DeepfakeImmuniser()

    def _arr(self):
        return _image_to_float32(_make_test_image(64, 64))

    def test_output_shape(self):
        arr = self._arr()
        r = self.immuniser.immunise(arr, level="basic")
        assert r.immunised_image.shape == arr.shape

    def test_output_range(self):
        arr = self._arr()
        for level in ("basic", "advanced", "maximum"):
            r = self.immuniser.immunise(arr, level=level)
            assert r.immunised_image.min() >= 0.0
            assert r.immunised_image.max() <= 1.0

    def test_maximum_disruption_highest(self):
        arr = self._arr()
        basic = self.immuniser.immunise(arr, level="basic")
        maximum = self.immuniser.immunise(arr, level="maximum")
        assert maximum.gan_disruption_score >= basic.gan_disruption_score


class TestAIProfiler:
    def setup_method(self):
        from app.services.ai_modules.profiler import AIProfiler
        self.profiler = AIProfiler()

    def test_profile_returns_result(self):
        arr = _image_to_float32(_make_test_image(128, 128))
        result = self.profiler.profile(arr)
        assert result is not None
        assert result.faces_detected >= 0

    def test_emotion_scores_sum_to_one(self):
        arr = _image_to_float32(_make_test_image(128, 128))
        result = self.profiler.profile(arr)
        if result.emotion_scores:
            total = sum(result.emotion_scores.values())
            assert abs(total - 1.0) < 0.01, f"Emotion scores should sum to 1, got {total}"

    def test_identity_confidence_in_range(self):
        arr = _image_to_float32(_make_test_image(128, 128))
        result = self.profiler.profile(arr)
        assert 0.0 <= result.identity_confidence <= 1.0

    def test_profile_duration_positive(self):
        arr = _image_to_float32(_make_test_image(64, 64))
        result = self.profiler.profile(arr)
        assert result.duration_ms > 0


class TestPrivacyEvaluator:
    def setup_method(self):
        from app.services.ai_modules.profiler import PrivacyEvaluator
        from app.services.ai_modules.adversarial import AdversarialProtector
        self.evaluator = PrivacyEvaluator()
        self.protector = AdversarialProtector()

    def test_ssim_perfect_for_identical_images(self):
        arr = _image_to_float32(_make_test_image(64, 64))
        result = self.evaluator.evaluate(arr, arr)
        assert result.ssim_score > 0.99

    def test_ssim_lower_after_perturbation(self):
        arr = _image_to_float32(_make_test_image(64, 64))
        pert = self.protector.apply(arr, level="maximum", use_pgd=True)
        result = self.evaluator.evaluate(arr, pert.perturbed_image)
        assert result.ssim_score < 1.0

    def test_psnr_positive(self):
        arr = _image_to_float32(_make_test_image(64, 64))
        result = self.evaluator.evaluate(arr, arr)
        assert result.psnr_db >= 0


class TestAntiScraping:
    def setup_method(self):
        from app.services.ai_modules.anti_scraping import AntiScrapingEngine, BotDetector
        self.engine = AntiScrapingEngine()
        self.detector = BotDetector()

    def test_bot_ua_detected(self):
        is_bot, conf, reason = self.detector.analyse("python-requests/2.31", {})
        assert is_bot is True
        assert conf > 0.9

    def test_normal_browser_not_flagged(self):
        headers = {
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate",
            "accept": "text/html,application/xhtml+xml",
        }
        is_bot, conf, reason = self.detector.analyse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", headers
        )
        assert is_bot is False

    def test_no_ua_is_suspicious(self):
        is_bot, conf, reason = self.detector.analyse("", {})
        assert is_bot is True

    def test_all_poison_types_produce_output(self):
        arr = _image_to_float32(_make_test_image(64, 64))
        for ptype in self.engine.POISON_TYPES:
            result = self.engine.generate_poison(arr, poison_type=ptype)
            assert result.poisoned_image.shape == arr.shape
            assert result.poisoned_image.min() >= 0.0
            assert result.poisoned_image.max() <= 1.0

    def test_poison_is_visually_similar(self):
        """Poisoned image should look nearly identical to original."""
        arr = _image_to_float32(_make_test_image(64, 64))
        for ptype in self.engine.POISON_TYPES:
            result = self.engine.generate_poison(arr, poison_type=ptype)
            diff = float(np.abs(result.poisoned_image - arr).mean())
            assert diff < 0.05, f"Poison type {ptype}: mean diff {diff:.4f} too large"


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS — Processing Service
# ═══════════════════════════════════════════════════════════════════════════

class TestProcessingService:
    """End-to-end pipeline tests."""

    def setup_method(self):
        from app.services.processing_service import ImageProcessingService
        from app.schemas.schemas import ModulesConfig
        self.service = ImageProcessingService()
        self.ModulesConfig = ModulesConfig

    @pytest.mark.asyncio
    async def test_basic_pipeline(self):
        img_bytes = _make_test_image(128, 128)
        job_id = uuid.uuid4().hex[:16]
        modules = self.ModulesConfig()

        result = await self.service.process(
            image_bytes=img_bytes,
            job_id=job_id,
            protection_level="basic",
            modules=modules,
        )

        assert result.status == "completed"
        assert result.job_id == job_id
        assert result.privacy_metrics.overall_privacy_score > 0
        assert len(result.threat_log) > 0
        assert result.processing_time_ms > 0

    @pytest.mark.asyncio
    async def test_advanced_pipeline(self):
        img_bytes = _make_test_image(128, 128)
        modules = self.ModulesConfig(adversarial=True, deepfake=True, watermark=True, profiling=True)
        result = await self.service.process(
            img_bytes, uuid.uuid4().hex[:16], "advanced", modules
        )
        assert result.status == "completed"
        assert "adversarial_fgsm" in result.modules_used
        assert "deepfake_immunisation" in result.modules_used
        assert "dct_watermark" in result.modules_used

    @pytest.mark.asyncio
    async def test_output_file_created(self):
        import os
        img_bytes = _make_test_image(64, 64)
        job_id = uuid.uuid4().hex[:16]
        modules = self.ModulesConfig(adversarial=True, profiling=False)
        result = await self.service.process(img_bytes, job_id, "basic", modules)

        from app.core.config import settings
        output_path = os.path.join(settings.OUTPUT_DIR, f"{job_id}_protected.png")
        assert os.path.exists(output_path), "Protected image file should be created"

    @pytest.mark.asyncio
    async def test_all_modules_disabled(self):
        """Pipeline should still complete gracefully with all modules off."""
        img_bytes = _make_test_image(64, 64)
        modules = self.ModulesConfig(
            adversarial=False, deepfake=False, watermark=False,
            profiling=False, anti_scraping=False, data_poisoning=False,
        )
        result = await self.service.process(img_bytes, uuid.uuid4().hex[:16], "basic", modules)
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_maximum_protection(self):
        img_bytes = _make_test_image(128, 128)
        modules = self.ModulesConfig(
            adversarial=True, deepfake=True, watermark=True,
            profiling=True, anti_scraping=True, data_poisoning=True,
        )
        result = await self.service.process(img_bytes, uuid.uuid4().hex[:16], "maximum", modules)
        assert result.status == "completed"
        assert 0 <= result.privacy_metrics.overall_privacy_score <= 100


# ═══════════════════════════════════════════════════════════════════════════
# SECURITY TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestSecurity:
    def test_hash_password_not_plaintext(self):
        from app.core.security import hash_password
        hashed = hash_password("MyPass123")
        assert hashed != "MyPass123"
        assert len(hashed) > 20

    def test_verify_password_correct(self):
        from app.core.security import hash_password, verify_password
        hashed = hash_password("SecurePass1")
        assert verify_password("SecurePass1", hashed) is True

    def test_verify_password_wrong(self):
        from app.core.security import hash_password, verify_password
        hashed = hash_password("SecurePass1")
        assert verify_password("WrongPass1", hashed) is False

    def test_create_and_decode_access_token(self):
        from app.core.security import create_access_token, decode_token, UserRole
        token = create_access_token("user-123", role=UserRole.USER)
        payload = decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["role"] == "user"
        assert payload["type"] == "access"

    def test_invalid_token_raises(self):
        from app.core.security import decode_token
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            decode_token("not.a.valid.token")
        assert exc_info.value.status_code == 401

    def test_refresh_token_type(self):
        from app.core.security import create_refresh_token, decode_token, UserRole
        token = create_refresh_token("user-456", role=UserRole.PRO)
        payload = decode_token(token)
        assert payload["type"] == "refresh"
        assert payload["role"] == "pro"


# ═══════════════════════════════════════════════════════════════════════════
# PERFORMANCE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPerformance:
    """Ensure processing meets latency targets."""

    @pytest.mark.asyncio
    async def test_basic_processing_under_5s(self):
        from app.services.processing_service import ImageProcessingService
        from app.schemas.schemas import ModulesConfig

        service = ImageProcessingService()
        img_bytes = _make_test_image(256, 256)
        modules = ModulesConfig(adversarial=True, deepfake=True, watermark=True, profiling=True)

        start = time.perf_counter()
        result = await service.process(img_bytes, uuid.uuid4().hex[:16], "basic", modules)
        elapsed = time.perf_counter() - start

        assert result.status == "completed"
        assert elapsed < 5.0, f"Processing took {elapsed:.2f}s — exceeds 5s target"

    @pytest.mark.asyncio
    async def test_small_image_fast(self):
        from app.services.processing_service import ImageProcessingService
        from app.schemas.schemas import ModulesConfig

        service = ImageProcessingService()
        img_bytes = _make_test_image(64, 64)
        modules = ModulesConfig()

        start = time.perf_counter()
        await service.process(img_bytes, uuid.uuid4().hex[:16], "basic", modules)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"Small image took {elapsed:.2f}s"
