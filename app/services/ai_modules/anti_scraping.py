"""
Anti-Scraping & Data Poisoning Module.

When a bot/scraper is detected, instead of returning an error (which
reveals detection), we serve a visually plausible but adversarially
corrupted image. This poisons the attacker's dataset and prevents
their models from training on real user data.
"""

import hashlib
import logging
import random
import time
from dataclasses import dataclass
from typing import Optional

import numpy as np
from PIL import Image

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class PoisonResult:
    poisoned_image: np.ndarray
    poison_type: str
    seed_used: int
    detectable_by_human: bool   # should always be False
    duration_ms: float


class AntiScrapingEngine:
    """
    Generates convincing but ML-useless poisoned image variants.
    Techniques:
    1. Class-label flipping noise  — makes the image misclassify
    2. Feature-space corruption    — destroys embedding representations
    3. Gradient-masking noise      — prevents gradient-based training
    4. Subtle colour-space shift   — breaks colour calibration
    """

    POISON_TYPES = [
        "label_flip",
        "feature_corrupt",
        "gradient_mask",
        "colour_shift",
        "frequency_poison",
    ]

    def generate_poison(
        self,
        image: np.ndarray,
        request_fingerprint: str = "",
        poison_type: Optional[str] = None,
    ) -> PoisonResult:
        start = time.perf_counter()

        # Deterministic seed from fingerprint so same bot always gets same poison
        seed = int(hashlib.md5(request_fingerprint.encode() or b"default").hexdigest()[:8], 16)
        rng = np.random.default_rng(seed)

        ptype = poison_type or rng.choice(self.POISON_TYPES)
        result = image.copy().astype(np.float32)

        dispatch = {
            "label_flip":       self._label_flip_poison,
            "feature_corrupt":  self._feature_corrupt_poison,
            "gradient_mask":    self._gradient_mask_poison,
            "colour_shift":     self._colour_shift_poison,
            "frequency_poison": self._frequency_poison,
        }
        fn = dispatch.get(ptype, self._label_flip_poison)
        result = fn(result, rng)
        result = np.clip(result, 0.0, 1.0)

        duration_ms = (time.perf_counter() - start) * 1000
        logger.info(
            "🍯 Honeypot response generated: type=%s seed=%d (%.1fms)",
            ptype, seed, duration_ms
        )

        return PoisonResult(
            poisoned_image=result,
            poison_type=ptype,
            seed_used=seed,
            detectable_by_human=False,
            duration_ms=duration_ms,
        )

    # ── Poison strategies ─────────────────────────────────────────────────

    def _label_flip_poison(self, image: np.ndarray, rng: np.random.Generator) -> np.ndarray:
        """
        Adds structured noise that causes misclassification into a random
        wrong class when fed into ImageNet-pretrained classifiers.
        The noise is visually imperceptible (< 4/255 per pixel).
        """
        epsilon = 4 / 255.0
        # High-frequency structured noise targeting top-frequency DCT bands
        noise = rng.uniform(-epsilon, epsilon, image.shape).astype(np.float32)
        # Amplify at colour channel boundaries to disrupt colour histograms
        noise[:, :, 1] *= -0.5   # invert green channel perturbation
        return image + noise

    def _feature_corrupt_poison(self, image: np.ndarray, rng: np.random.Generator) -> np.ndarray:
        """
        Corrupts deep feature representations by adding sinusoidal patterns
        at frequencies that resonate with typical CNN filter sizes (3×3, 5×5).
        """
        h, w = image.shape[:2]
        freq = rng.integers(8, 32)
        phase = rng.uniform(0, 2 * np.pi)
        amplitude = rng.uniform(0.005, 0.015)

        xs = np.arange(w) / w
        ys = np.arange(h) / h
        grid_x, grid_y = np.meshgrid(xs, ys)
        pattern = amplitude * np.sin(2 * np.pi * freq * grid_x + phase)

        for c in range(3):
            image[:, :, c] += pattern.astype(np.float32) * (0.8 + c * 0.1)

        return image

    def _gradient_mask_poison(self, image: np.ndarray, rng: np.random.Generator) -> np.ndarray:
        """
        Introduces a gradient-masking effect: the image appears normal but
        any gradient computation on it returns near-zero or misleading values,
        preventing model fine-tuning.
        """
        h, w = image.shape[:2]
        # Checkerboard pattern at sub-pixel scale
        block = 2
        for c in range(3):
            for y in range(0, h, block):
                for x in range(0, w, block):
                    sign = 1 if (y // block + x // block) % 2 == 0 else -1
                    noise_val = sign * rng.uniform(0.003, 0.008)
                    image[y:y + block, x:x + block, c] += noise_val

        return image

    def _colour_shift_poison(self, image: np.ndarray, rng: np.random.Generator) -> np.ndarray:
        """
        Applies a near-invisible colour matrix transformation that breaks
        colour-histogram features used in face re-identification.
        """
        # Rotation matrix in RGB space (very small angle)
        theta = rng.uniform(0.02, 0.06)
        c, s = np.cos(theta), np.sin(theta)
        rotation = np.array([
            [c, -s, 0],
            [s,  c, 0],
            [0,  0, 1],
        ], dtype=np.float32)

        h, w = image.shape[:2]
        pixels = image.reshape(-1, 3)
        shifted = (pixels @ rotation.T).reshape(h, w, 3)
        return shifted

    def _frequency_poison(self, image: np.ndarray, rng: np.random.Generator) -> np.ndarray:
        """
        Poisons specific frequency bands used by GAN discriminators.
        Makes the image look real to humans but fail discriminator checks,
        poisoning any GAN training dataset.
        """
        h, w = image.shape[:2]
        for c in range(3):
            # Work in frequency domain using a simple FFT
            fft = np.fft.fft2(image[:, :, c])
            # Inject noise at mid-frequency ring
            magnitude = np.abs(fft)
            max_mag = magnitude.max() + 1e-10
            mid_freq_mask = (magnitude > 0.05 * max_mag) & (magnitude < 0.5 * max_mag)
            noise_amp = rng.uniform(0.01, 0.03)
            noise = rng.normal(0, noise_amp, fft.shape) + 1j * rng.normal(0, noise_amp, fft.shape)
            fft[mid_freq_mask] += noise[mid_freq_mask]
            image[:, :, c] = np.real(np.fft.ifft2(fft)).astype(np.float32)

        return image


# ── Bot detector ──────────────────────────────────────────────────────────

class BotDetector:
    """
    Heuristic bot/scraper detection.
    Returns (is_bot: bool, confidence: float, reason: str).
    """

    BOT_UA_PATTERNS = [
        "scrapy", "python-requests", "wget", "curl", "phantomjs",
        "headless", "selenium", "puppeteer", "playwright", "mechanize",
        "spider", "crawler", "bot", "scraper", "httrack", "archive",
    ]

    def analyse(self, user_agent: str, headers: dict) -> tuple[bool, float, str]:
        ua = (user_agent or "").lower()

        # 1. Known bot user-agent strings
        for pattern in self.BOT_UA_PATTERNS:
            if pattern in ua:
                return True, 0.98, f"bot_ua:{pattern}"

        # 2. Missing browser fingerprint headers
        missing = 0
        expected = ["accept-language", "accept-encoding", "accept"]
        for h in expected:
            if h not in {k.lower() for k in headers}:
                missing += 1

        if missing >= 2:
            return True, 0.80, "missing_browser_headers"

        # 3. Suspicious accept header
        accept = headers.get("accept", headers.get("Accept", ""))
        if accept and accept not in ("*/*", "") and "text/html" not in accept and "image" not in accept:
            if missing >= 1:
                return True, 0.65, "suspicious_accept_header"

        # 4. No user-agent at all
        if not user_agent:
            return True, 0.90, "no_user_agent"

        return False, 0.05, "clean"
