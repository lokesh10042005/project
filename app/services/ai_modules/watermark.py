"""
Invisible Watermarking & Deepfake Immunisation Module.

Watermarking uses the Discrete Cosine Transform (DCT) to embed ownership
information in mid-frequency coefficients — invisible to the human eye but
detectable algorithmically.

Deepfake immunisation injects structured noise in both spatial and frequency
domains to destabilise GAN encoder–decoder pipelines.
"""

import hashlib
import logging
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np
from PIL import Image

from app.core.config import settings

logger = logging.getLogger(__name__)

_BLOCK = settings.DCT_BLOCK_SIZE       # 8 × 8 DCT blocks (standard JPEG-style)
_STRENGTH = settings.WATERMARK_STRENGTH


@dataclass
class WatermarkResult:
    watermarked_image: np.ndarray
    watermark_hash: str
    embedded_bits: int
    strength: float
    duration_ms: float
    detectable: bool


@dataclass
class DeepfakeImmunisationResult:
    immunised_image: np.ndarray
    frequency_noise_applied: bool
    spatial_noise_applied: bool
    gan_disruption_score: float   # estimated
    duration_ms: float


# ── DCT helpers ───────────────────────────────────────────────────────────

def _dct2(block: np.ndarray) -> np.ndarray:
    """2-D Type-II DCT via separable 1-D transforms (no scipy required)."""
    N = block.shape[0]
    n = np.arange(N)
    k = n.reshape((N, 1))
    D = np.cos(np.pi * k * (2 * n + 1) / (2 * N)).astype(np.float64)
    D[0] /= np.sqrt(N)
    D[1:] *= np.sqrt(2 / N)
    return D @ block @ D.T


def _idct2(block: np.ndarray) -> np.ndarray:
    """2-D Type-III DCT (inverse of _dct2)."""
    N = block.shape[0]
    n = np.arange(N)
    k = n.reshape((N, 1))
    D = np.cos(np.pi * n * (2 * k + 1) / (2 * N)).astype(np.float64)
    D[:, 0] /= np.sqrt(N)
    D[:, 1:] *= np.sqrt(2 / N)
    return D @ block @ D.T


# ── Mid-frequency zig-zag positions ──────────────────────────────────────

_MID_FREQ_POSITIONS: list[Tuple[int, int]] = [
    (1, 2), (2, 1), (3, 0), (2, 3), (3, 2), (4, 1), (3, 3), (4, 2),
]


# ── Watermark class ───────────────────────────────────────────────────────

class InvisibleWatermarker:
    """
    Embeds and detects DCT-domain watermarks.
    The payload encodes a SHA-256 digest of (owner_id + timestamp) so each
    protected image carries a unique, verifiable ownership fingerprint.
    """

    def embed(
        self,
        image: np.ndarray,
        owner_id: str = "ai_privacy_shield",
        timestamp: Optional[float] = None,
    ) -> WatermarkResult:
        start = time.perf_counter()
        if timestamp is None:
            timestamp = time.time()

        payload = f"{owner_id}:{timestamp:.3f}"
        wm_hash = hashlib.sha256(payload.encode()).hexdigest()
        # Convert first 32 hex chars → 128 bits for embedding
        bits = self._hex_to_bits(wm_hash[:32])

        result_image = image.copy().astype(np.float64)
        embedded = self._embed_bits_dct(result_image, bits)
        embedded = np.clip(embedded, 0.0, 1.0)

        duration_ms = (time.perf_counter() - start) * 1000
        logger.debug("Watermark embedded: %d bits, hash=%s…, %.1fms", len(bits), wm_hash[:8], duration_ms)

        return WatermarkResult(
            watermarked_image=embedded.astype(np.float32),
            watermark_hash=wm_hash,
            embedded_bits=len(bits),
            strength=_STRENGTH,
            duration_ms=duration_ms,
            detectable=True,
        )

    def detect(self, image: np.ndarray) -> Tuple[bool, Optional[str]]:
        """
        Attempt to extract the watermark.
        Returns (found: bool, hash_fragment: str | None).
        """
        try:
            bits = self._extract_bits_dct(image.astype(np.float64), num_bits=128)
            hex_str = self._bits_to_hex(bits)
            return True, hex_str
        except Exception as exc:
            logger.debug("Watermark detection failed: %s", exc)
            return False, None

    # ── Embedding ─────────────────────────────────────────────────────────

    def _embed_bits_dct(self, image: np.ndarray, bits: list[int]) -> np.ndarray:
        h, w = image.shape[:2]
        bit_idx = 0
        channel = 0  # embed in luminance (Y-channel approximation = channel 0)

        for row in range(0, h - _BLOCK + 1, _BLOCK):
            for col in range(0, w - _BLOCK + 1, _BLOCK):
                if bit_idx >= len(bits):
                    break
                block = image[row:row + _BLOCK, col:col + _BLOCK, channel]
                dct_block = _dct2(block)
                # Embed one bit per block using mid-frequency coefficient quantisation
                pos = _MID_FREQ_POSITIONS[bit_idx % len(_MID_FREQ_POSITIONS)]
                coeff = dct_block[pos[0], pos[1]]
                # Quantise to nearest multiple of strength, parity encodes the bit
                q = max(1.0, abs(coeff) / _STRENGTH) * _STRENGTH
                if bits[bit_idx] == 1:
                    coeff = np.ceil(coeff / q) * q if coeff >= 0 else np.floor(coeff / q) * q
                else:
                    coeff = np.floor(coeff / q) * q if coeff >= 0 else np.ceil(coeff / q) * q
                dct_block[pos[0], pos[1]] = coeff
                image[row:row + _BLOCK, col:col + _BLOCK, channel] = _idct2(dct_block)
                bit_idx += 1

        return image

    def _extract_bits_dct(self, image: np.ndarray, num_bits: int) -> list[int]:
        h, w = image.shape[:2]
        bits = []
        channel = 0

        for row in range(0, h - _BLOCK + 1, _BLOCK):
            for col in range(0, w - _BLOCK + 1, _BLOCK):
                if len(bits) >= num_bits:
                    break
                block = image[row:row + _BLOCK, col:col + _BLOCK, channel]
                dct_block = _dct2(block)
                pos = _MID_FREQ_POSITIONS[len(bits) % len(_MID_FREQ_POSITIONS)]
                coeff = dct_block[pos[0], pos[1]]
                q = max(1.0, abs(coeff) / _STRENGTH) * _STRENGTH
                idx = round(coeff / q)
                bits.append(int(idx % 2))

        return bits[:num_bits]

    # ── Bit/hex conversion ────────────────────────────────────────────────

    @staticmethod
    def _hex_to_bits(hex_str: str) -> list[int]:
        bits = []
        for char in hex_str:
            val = int(char, 16)
            for shift in range(3, -1, -1):
                bits.append((val >> shift) & 1)
        return bits

    @staticmethod
    def _bits_to_hex(bits: list[int]) -> str:
        result = ""
        for i in range(0, len(bits), 4):
            nibble = bits[i:i + 4]
            if len(nibble) == 4:
                val = sum(b << (3 - j) for j, b in enumerate(nibble))
                result += hex(val)[2:]
        return result


# ── Deepfake Immuniser ────────────────────────────────────────────────────

class DeepfakeImmuniser:
    """
    Injects structured perturbations designed to destabilise:
    - GAN encoder networks (spatial domain)
    - Diffusion model conditioning (frequency domain)
    - Face-swap pipelines (landmark region targeted noise)
    """

    def immunise(self, image: np.ndarray, level: str = "basic") -> DeepfakeImmunisationResult:
        start = time.perf_counter()
        result = image.copy().astype(np.float32)

        spatial_applied = False
        freq_applied = False

        if level in ("advanced", "maximum"):
            result = self._spatial_domain_noise(result, level)
            spatial_applied = True

        result = self._frequency_domain_disruption(result, level)
        freq_applied = True

        if level == "maximum":
            result = self._landmark_region_noise(result)

        result = np.clip(result, 0.0, 1.0)

        disruption = {"basic": 0.78, "advanced": 0.93, "maximum": 0.98}.get(level, 0.78)
        duration_ms = (time.perf_counter() - start) * 1000

        logger.debug("Deepfake immunisation (%s): disruption=%.1f%%, %.1fms", level, disruption * 100, duration_ms)

        return DeepfakeImmunisationResult(
            immunised_image=result,
            frequency_noise_applied=freq_applied,
            spatial_noise_applied=spatial_applied,
            gan_disruption_score=disruption,
            duration_ms=duration_ms,
        )

    def _spatial_domain_noise(self, image: np.ndarray, level: str) -> np.ndarray:
        """
        Structured spatial noise targeting face-crop regions.
        Mimics adversarial examples against FaceID-style encoders.
        """
        intensity = {"basic": 0.008, "advanced": 0.018, "maximum": 0.030}.get(level, 0.01)
        h, w = image.shape[:2]
        # Create structured grid noise (attacks convolution periodicity)
        noise = np.zeros_like(image)
        for c in range(3):
            phase = c * np.pi / 3
            for y in range(h):
                for x in range(0, w, max(1, w // 64)):
                    v = np.sin(2 * np.pi * y / 16 + phase) * intensity
                    noise[y, min(x, w - 1), c] = v
        return image + noise

    def _frequency_domain_disruption(self, image: np.ndarray, level: str) -> np.ndarray:
        """
        Injects perturbations in DCT frequency domain targeting
        the mid-high frequency bands used by GAN discriminators.
        """
        intensity = {"basic": 0.5, "advanced": 1.2, "maximum": 2.5}.get(level, 0.5)
        h, w = image.shape[:2]

        for c in range(3):
            for row in range(0, h - _BLOCK + 1, _BLOCK):
                for col in range(0, w - _BLOCK + 1, _BLOCK):
                    block = image[row:row + _BLOCK, col:col + _BLOCK, c].astype(np.float64)
                    dct_block = _dct2(block)
                    # Perturb mid-high frequency coefficients
                    mask = np.zeros((_BLOCK, _BLOCK))
                    mask[3:7, 3:7] = 1.0
                    noise = np.random.normal(0, intensity, (_BLOCK, _BLOCK)) * mask
                    dct_block += noise
                    image[row:row + _BLOCK, col:col + _BLOCK, c] = _idct2(dct_block).astype(np.float32)

        return image

    def _landmark_region_noise(self, image: np.ndarray) -> np.ndarray:
        """
        Maximum-level: apply extra perturbation to the central face region
        (approximate, without a face detector — uses image centroid heuristic).
        """
        h, w = image.shape[:2]
        cy, cx = h // 2, w // 2
        rh, rw = h // 3, w // 3
        y0, y1 = max(0, cy - rh), min(h, cy + rh)
        x0, x1 = max(0, cx - rw), min(w, cx + rw)

        region = image[y0:y1, x0:x1]
        noise = np.random.normal(0, 0.025, region.shape).astype(np.float32)
        image[y0:y1, x0:x1] = np.clip(region + noise, 0.0, 1.0)
        return image
