"""
AI Profiling Module.
Analyses image attributes (age, emotion, identity confidence) using
pretrained model inference — providing interpretability insights and
measuring what an attacker's system would see pre/post protection.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import List, Tuple

import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)


@dataclass
class FaceRegion:
    x: int
    y: int
    width: int
    height: int
    confidence: float


@dataclass
class ProfileResult:
    faces_detected: int
    face_regions: List[FaceRegion]
    estimated_age_range: str
    dominant_emotion: str
    emotion_scores: dict
    identity_confidence: float      # 0–1 (how confident a recogniser would be)
    skin_tone_cluster: str
    glasses_detected: bool
    gender_estimate: str
    duration_ms: float
    model_version: str = "aps-profiler-v2"


@dataclass
class PrivacyEvaluationResult:
    original_metrics: ProfileResult
    protected_metrics: ProfileResult
    recognition_confidence_reduction: float   # % reduction
    attribute_obfuscation_score: float        # 0–1
    overall_protection_effectiveness: float  # 0–1
    ssim_score: float
    psnr_db: float
    l2_perturbation: float


# ── Profiler ──────────────────────────────────────────────────────────────

class AIProfiler:
    """
    Runs attribute analysis on an image to simulate what commercial
    AI systems (Google Vision, AWS Rekognition, Azure Face) would detect.

    In production: swap the stub inference calls with actual model calls
    (e.g., DeepFace, InsightFace, torchvision) depending on deployment env.
    """

    EMOTIONS = ["neutral", "happy", "sad", "angry", "surprised", "fearful", "disgusted"]
    AGE_RANGES = ["0–12", "13–17", "18–25", "26–35", "36–45", "46–60", "60+"]

    def profile(self, image: np.ndarray) -> ProfileResult:
        start = time.perf_counter()

        faces = self._detect_faces(image)

        if not faces:
            return ProfileResult(
                faces_detected=0, face_regions=[],
                estimated_age_range="N/A", dominant_emotion="N/A",
                emotion_scores={}, identity_confidence=0.0,
                skin_tone_cluster="N/A", glasses_detected=False,
                gender_estimate="N/A",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Analyse primary (largest) face
        primary = max(faces, key=lambda f: f.width * f.height)
        face_crop = self._crop_face(image, primary, padding=0.2)

        emotion_scores = self._estimate_emotions(face_crop)
        dominant_emotion = max(emotion_scores, key=emotion_scores.get)
        age_range = self._estimate_age(face_crop)
        identity_conf = self._estimate_identity_confidence(face_crop)
        skin_tone = self._estimate_skin_tone(face_crop)
        glasses = self._detect_glasses(face_crop)
        gender = self._estimate_gender(face_crop)

        duration_ms = (time.perf_counter() - start) * 1000
        logger.debug("Profiling: %d faces, emotion=%s, age=%s, id_conf=%.2f  (%.1fms)",
                     len(faces), dominant_emotion, age_range, identity_conf, duration_ms)

        return ProfileResult(
            faces_detected=len(faces),
            face_regions=faces,
            estimated_age_range=age_range,
            dominant_emotion=dominant_emotion,
            emotion_scores=emotion_scores,
            identity_confidence=identity_conf,
            skin_tone_cluster=skin_tone,
            glasses_detected=glasses,
            gender_estimate=gender,
            duration_ms=duration_ms,
        )

    # ── Face detection (Haar-cascade approximation) ───────────────────────

    def _detect_faces(self, image: np.ndarray) -> List[FaceRegion]:
        """
        Lightweight face detection heuristic.
        In production: replace with cv2.CascadeClassifier, MTCNN, or RetinaFace.
        """
        h, w = image.shape[:2]
        # Skin-tone detection heuristic in YCbCr-like space
        r, g, b = image[:, :, 0], image[:, :, 1], image[:, :, 2]
        # Skin: R > 0.35, G between 0.20–0.75, B < 0.60, R > G > B roughly
        skin_mask = (
            (r > 0.35) & (r > g) & (r > b) &
            (g > 0.20) & (g < 0.75) &
            (b < 0.62) &
            (np.abs(r - g) > 0.03)
        )
        skin_ratio = skin_mask.mean()

        if skin_ratio < 0.03:
            return []  # No skin tones detected

        # Find bounding box of largest skin region
        rows = np.any(skin_mask, axis=1)
        cols = np.any(skin_mask, axis=0)
        if not rows.any() or not cols.any():
            return []

        rmin, rmax = np.where(rows)[0][[0, -1]]
        cmin, cmax = np.where(cols)[0][[0, -1]]
        rh, rw = int(rmax - rmin), int(cmax - cmin)

        if rh < 10 or rw < 10:
            return []

        return [FaceRegion(
            x=int(cmin), y=int(rmin), width=rw, height=rh,
            confidence=min(0.99, 0.5 + skin_ratio * 3.0),
        )]

    def _crop_face(self, image: np.ndarray, face: FaceRegion, padding: float) -> np.ndarray:
        h, w = image.shape[:2]
        px, py = int(face.width * padding), int(face.height * padding)
        y0 = max(0, face.y - py)
        y1 = min(h, face.y + face.height + py)
        x0 = max(0, face.x - px)
        x1 = min(w, face.x + face.width + px)
        return image[y0:y1, x0:x1]

    # ── Attribute estimators ──────────────────────────────────────────────

    def _estimate_emotions(self, face: np.ndarray) -> dict:
        """Estimate emotion distribution from pixel statistics."""
        brightness = face.mean()
        contrast = face.std()

        # Heuristic mapping: high brightness → happy, low → sad, etc.
        scores = {
            "neutral":    float(max(0, 0.4 - abs(brightness - 0.5) * 2)),
            "happy":      float(max(0, brightness * 0.6)),
            "sad":        float(max(0, (1 - brightness) * 0.4)),
            "angry":      float(max(0, contrast * 0.5)),
            "surprised":  float(max(0, contrast * 0.3)),
            "fearful":    float(0.05),
            "disgusted":  float(0.03),
        }
        # Normalise to sum to 1
        total = sum(scores.values()) or 1.0
        return {k: round(v / total, 3) for k, v in scores.items()}

    def _estimate_age(self, face: np.ndarray) -> str:
        """Estimate age range from texture complexity (proxy)."""
        std = float(face.std())
        # Higher texture std → older skin
        idx = min(len(self.AGE_RANGES) - 1, int(std * 20))
        return self.AGE_RANGES[max(0, idx)]

    def _estimate_identity_confidence(self, face: np.ndarray) -> float:
        """
        Estimate how confidently a recognition system could identify this face.
        Uses feature diversity as proxy (more unique texture → higher confidence).
        """
        if face.size == 0:
            return 0.0
        entropy = self._image_entropy(face)
        return float(min(0.99, entropy / 8.0))

    def _estimate_skin_tone(self, face: np.ndarray) -> str:
        """Cluster average skin tone into Fitzpatrick-inspired buckets."""
        if face.size == 0:
            return "unknown"
        avg = face.mean(axis=(0, 1))
        r, g, b = float(avg[0]), float(avg[1]), float(avg[2])
        brightness = (r + g + b) / 3
        if brightness > 0.75:
            return "very_light"
        elif brightness > 0.60:
            return "light"
        elif brightness > 0.45:
            return "medium"
        elif brightness > 0.30:
            return "medium_dark"
        else:
            return "dark"

    def _detect_glasses(self, face: np.ndarray) -> bool:
        """Detect glasses via high-contrast horizontal edge density in eye region."""
        if face.shape[0] < 10:
            return False
        # Eye region: approximately 25–50% from top
        h = face.shape[0]
        eye_region = face[h // 4: h // 2]
        if eye_region.size == 0:
            return False
        # Glasses create strong horizontal gradients
        gray = eye_region.mean(axis=2)
        h_grad = np.abs(np.diff(gray, axis=0)).mean()
        return bool(h_grad > 0.08)

    def _estimate_gender(self, face: np.ndarray) -> str:
        """
        Estimate gender presentation from colour/texture (very rough proxy).
        NOTE: gender estimation from images is inherently biased and unreliable.
        This is intentionally simple and should NOT be used for real decisions.
        """
        if face.size == 0:
            return "unknown"
        r_ratio = float(face[:, :, 0].mean()) / (face.mean() + 1e-6)
        return "feminine" if r_ratio > 1.02 else "masculine"

    @staticmethod
    def _image_entropy(image: np.ndarray) -> float:
        """Shannon entropy of pixel intensity histogram."""
        gray = image.mean(axis=2)
        hist, _ = np.histogram(gray, bins=256, range=(0, 1))
        hist = hist / (hist.sum() + 1e-10)
        nonzero = hist[hist > 0]
        return float(-np.sum(nonzero * np.log2(nonzero)))


# ── Privacy Evaluator ─────────────────────────────────────────────────────

class PrivacyEvaluator:
    """
    Measures the effectiveness of protection by comparing AI profiling
    results before and after the protection pipeline.
    """

    def __init__(self):
        self._profiler = AIProfiler()

    def evaluate(
        self,
        original: np.ndarray,
        protected: np.ndarray,
    ) -> PrivacyEvaluationResult:
        orig_profile = self._profiler.profile(original)
        prot_profile = self._profiler.profile(protected)

        # Recognition confidence reduction
        orig_conf = orig_profile.identity_confidence
        prot_conf = prot_profile.identity_confidence
        conf_reduction = max(0.0, orig_conf - prot_conf) / (orig_conf + 1e-6)

        # Attribute obfuscation: how many attributes changed after protection
        changed = 0
        total = 4
        if orig_profile.dominant_emotion != prot_profile.dominant_emotion:
            changed += 1
        if orig_profile.estimated_age_range != prot_profile.estimated_age_range:
            changed += 1
        if abs(orig_profile.identity_confidence - prot_profile.identity_confidence) > 0.1:
            changed += 1
        if orig_profile.gender_estimate != prot_profile.gender_estimate:
            changed += 1
        obfuscation_score = changed / total

        # Image quality metrics
        ssim = self._ssim(original, protected)
        psnr = self._psnr(original, protected)
        l2 = float(np.linalg.norm(protected.astype(float) - original.astype(float)) /
                   np.sqrt(original.size))

        overall = (conf_reduction * 0.5 + ssim * 0.3 + obfuscation_score * 0.2)

        return PrivacyEvaluationResult(
            original_metrics=orig_profile,
            protected_metrics=prot_profile,
            recognition_confidence_reduction=conf_reduction,
            attribute_obfuscation_score=obfuscation_score,
            overall_protection_effectiveness=overall,
            ssim_score=ssim,
            psnr_db=psnr,
            l2_perturbation=l2,
        )

    @staticmethod
    def _ssim(a: np.ndarray, b: np.ndarray) -> float:
        C1, C2 = 0.01 ** 2, 0.03 ** 2
        scores = []
        for c in range(a.shape[2]):
            x, y = a[:, :, c].astype(float), b[:, :, c].astype(float)
            mu_x, mu_y = x.mean(), y.mean()
            sig_x = x.var()
            sig_y = y.var()
            sig_xy = float(np.mean((x - mu_x) * (y - mu_y)))
            num = (2 * mu_x * mu_y + C1) * (2 * sig_xy + C2)
            den = (mu_x ** 2 + mu_y ** 2 + C1) * (sig_x + sig_y + C2)
            scores.append(num / (den + 1e-10))
        return float(np.clip(np.mean(scores), 0, 1))

    @staticmethod
    def _psnr(a: np.ndarray, b: np.ndarray) -> float:
        mse = float(np.mean((a.astype(float) - b.astype(float)) ** 2))
        if mse < 1e-10:
            return 100.0
        return float(10 * np.log10(1.0 / mse))
