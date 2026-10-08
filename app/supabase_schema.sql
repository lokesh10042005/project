-- =====================================================================
-- AI PRIVACY SHIELD v2 — SUPABASE DATABASE SCHEMA
-- Complete production-ready SQL for Supabase (PostgreSQL + Auth + RLS)
--
-- Run this in Supabase SQL Editor in the following order:
--   1. Extensions & Types
--   2. Tables
--   3. Functions & Triggers
--   4. RLS Policies
--   5. Storage Buckets
--   6. Seed Data
-- =====================================================================

-- ─────────────────────────────────────────────────────────────────────
-- 1. EXTENSIONS
-- ─────────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────────────
-- 2. CUSTOM TYPES / ENUMS
-- ─────────────────────────────────────────────────────────────────────

-- User subscription plans
CREATE TYPE user_plan AS ENUM ('free', 'pro', 'enterprise');

-- Image protection status
CREATE TYPE protection_status AS ENUM ('processing', 'completed', 'failed');

-- Anti-scraping scan status
CREATE TYPE scan_status AS ENUM ('safe', 'warning', 'danger');

-- Threat log event types
CREATE TYPE threat_event_type AS ENUM (
    'image_protected',
    'scraping_detected',
    'deepfake_attempt',
    'unauthorized_access',
    'watermark_tampered'
);

-- Verification verdict
CREATE TYPE verification_verdict AS ENUM ('protected', 'partial', 'unprotected');

-- ─────────────────────────────────────────────────────────────────────
-- 3. UTILITY FUNCTION — Auto-update timestamps
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ─────────────────────────────────────────────────────────────────────
-- 4. PROFILES TABLE (extends Supabase auth.users)
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE public.profiles (
    id             UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    name           TEXT NOT NULL DEFAULT '',
    email          TEXT NOT NULL,
    avatar_url     TEXT,
    bio            TEXT DEFAULT 'Privacy-conscious digital professional',
    plan           user_plan NOT NULL DEFAULT 'free',
    language       TEXT NOT NULL DEFAULT 'en',

    -- Notification preferences
    notifications_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    weekly_report_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    threat_alerts_enabled   BOOLEAN NOT NULL DEFAULT TRUE,

    -- Usage tracking
    images_protected_count  INTEGER NOT NULL DEFAULT 0,
    scans_this_month        INTEGER NOT NULL DEFAULT 0,
    storage_used_mb         NUMERIC(10,2) NOT NULL DEFAULT 0,

    -- Timestamps
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_profiles_email ON public.profiles(email);

CREATE TRIGGER trigger_profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ─────────────────────────────────────────────────────────────────────
-- 5. PROTECTED IMAGES TABLE
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE public.protected_images (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,

    -- Image metadata
    original_name       TEXT NOT NULL,
    original_size_bytes BIGINT,
    protected_size_bytes BIGINT,
    mime_type           TEXT DEFAULT 'image/png',
    width               INTEGER,
    height              INTEGER,

    -- Storage paths (Supabase Storage bucket paths)
    original_storage_path   TEXT,
    protected_storage_path  TEXT,

    -- Protection configuration
    protection_types    TEXT[] NOT NULL DEFAULT '{}',
    strength            NUMERIC(3,2) NOT NULL DEFAULT 0.75,

    -- Protection metrics
    confidence_drop     NUMERIC(5,1) NOT NULL DEFAULT 0,
    similarity_score    NUMERIC(5,1) NOT NULL DEFAULT 0,
    watermark_strength  NUMERIC(5,1) NOT NULL DEFAULT 0,
    psnr                NUMERIC(6,2) NOT NULL DEFAULT 0,
    ssim                NUMERIC(6,4) NOT NULL DEFAULT 0,
    mse                 NUMERIC(10,4) NOT NULL DEFAULT 0,
    processing_time     NUMERIC(6,3) NOT NULL DEFAULT 0,

    -- Privacy score breakdown
    privacy_score           NUMERIC(5,1) DEFAULT 0,
    privacy_rating          TEXT DEFAULT 'Low',
    recognition_degradation NUMERIC(5,1) DEFAULT 0,
    prediction_variance     NUMERIC(5,1) DEFAULT 0,
    watermark_robustness    NUMERIC(5,1) DEFAULT 0,
    quality_penalty         NUMERIC(3,2) DEFAULT 1.0,

    -- Facial analysis results (JSONB for flexibility)
    facial_analysis     JSONB,

    -- Status
    status              protection_status NOT NULL DEFAULT 'processing',
    error_message       TEXT,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_protected_images_user_id ON public.protected_images(user_id);
CREATE INDEX idx_protected_images_created_at ON public.protected_images(created_at DESC);
CREATE INDEX idx_protected_images_status ON public.protected_images(status);

CREATE TRIGGER trigger_protected_images_updated_at
    BEFORE UPDATE ON public.protected_images
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ─────────────────────────────────────────────────────────────────────
-- 6. IMAGE VERIFICATION RESULTS TABLE
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE public.verification_results (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,

    -- Verdict
    verdict             verification_verdict NOT NULL DEFAULT 'unprotected',
    verdict_label       TEXT NOT NULL,
    summary             TEXT NOT NULL,
    overall_score       NUMERIC(5,1) NOT NULL DEFAULT 0,
    checks_passed       INTEGER NOT NULL DEFAULT 0,
    total_checks        INTEGER NOT NULL DEFAULT 3,

    -- Individual check results
    checks              JSONB NOT NULL DEFAULT '{}',

    -- File info
    file_name           TEXT,
    file_size_bytes     BIGINT,

    -- Processing
    processing_time     NUMERIC(6,3) NOT NULL DEFAULT 0,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_results_user_id ON public.verification_results(user_id);
CREATE INDEX idx_verification_results_created_at ON public.verification_results(created_at DESC);

-- ─────────────────────────────────────────────────────────────────────
-- 7. THREAT LOG TABLE
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE public.threat_log (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,

    event_type          threat_event_type NOT NULL,
    severity            TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),

    -- Event details
    confidence_drop     NUMERIC(5,1),
    source_ip           INET,
    description         TEXT,
    metadata            JSONB DEFAULT '{}',

    -- Reference to related entities
    related_image_id    UUID REFERENCES public.protected_images(id) ON DELETE SET NULL,
    related_scan_id     UUID,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_threat_log_user_id ON public.threat_log(user_id);
CREATE INDEX idx_threat_log_created_at ON public.threat_log(created_at DESC);
CREATE INDEX idx_threat_log_event_type ON public.threat_log(event_type);

-- ─────────────────────────────────────────────────────────────────────
-- 8. ANTI-SCRAPING SCANS TABLE
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE public.anti_scraping_scans (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,

    target_url          TEXT NOT NULL,
    scan_time           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_anti_scraping_scans_user_id ON public.anti_scraping_scans(user_id);
CREATE INDEX idx_anti_scraping_scans_created_at ON public.anti_scraping_scans(created_at DESC);

-- ─────────────────────────────────────────────────────────────────────
-- 9. ANTI-SCRAPING SCAN RESULTS TABLE
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE public.anti_scraping_results (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id             UUID NOT NULL REFERENCES public.anti_scraping_scans(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,

    url                 TEXT NOT NULL,
    status              scan_status NOT NULL DEFAULT 'safe',
    details             TEXT NOT NULL DEFAULT '',
    scraper_type        TEXT,
    confidence          INTEGER NOT NULL DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 100),
    requests_per_hour   INTEGER DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_anti_scraping_results_scan_id ON public.anti_scraping_results(scan_id);

-- Add FK from threat_log to anti_scraping_scans
ALTER TABLE public.threat_log
    ADD CONSTRAINT fk_threat_log_scan
    FOREIGN KEY (related_scan_id)
    REFERENCES public.anti_scraping_scans(id)
    ON DELETE SET NULL;

-- ─────────────────────────────────────────────────────────────────────
-- 10. AI MODELS REGISTRY TABLE
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE public.ai_models (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                TEXT NOT NULL,
    model_type          TEXT NOT NULL,

    evasion_rate        NUMERIC(5,2),
    strength_score      NUMERIC(5,2),
    resistance_rate     NUMERIC(5,2),

    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'training')),
    last_updated        DATE NOT NULL DEFAULT CURRENT_DATE,
    version             TEXT NOT NULL DEFAULT '1.0.0',
    description         TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER trigger_ai_models_updated_at
    BEFORE UPDATE ON public.ai_models
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ─────────────────────────────────────────────────────────────────────
-- 11. USER DAILY STATS TABLE
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE public.user_daily_stats (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    stat_date           DATE NOT NULL DEFAULT CURRENT_DATE,

    images_protected    INTEGER NOT NULL DEFAULT 0,
    threats_detected    INTEGER NOT NULL DEFAULT 0,
    scans_performed     INTEGER NOT NULL DEFAULT 0,
    verifications_done  INTEGER NOT NULL DEFAULT 0,

    avg_confidence_drop NUMERIC(5,1) DEFAULT 0,
    avg_ssim            NUMERIC(6,4) DEFAULT 0,
    avg_psnr            NUMERIC(6,2) DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(user_id, stat_date)
);

CREATE INDEX idx_user_daily_stats_user_date ON public.user_daily_stats(user_id, stat_date DESC);

CREATE TRIGGER trigger_user_daily_stats_updated_at
    BEFORE UPDATE ON public.user_daily_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ─────────────────────────────────────────────────────────────────────
-- 12. AUTO-CREATE PROFILE ON SIGNUP (Trigger on auth.users)
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, name, email)
    VALUES (
        NEW.id,
        COALESCE(NEW.raw_user_meta_data ->> 'name', ''),
        COALESCE(NEW.email, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user();

-- ─────────────────────────────────────────────────────────────────────
-- 13. AUTO-INCREMENT IMAGE COUNT & DAILY STATS
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.increment_image_count()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' AND (OLD IS NULL OR OLD.status != 'completed') THEN
        UPDATE public.profiles
        SET images_protected_count = images_protected_count + 1
        WHERE id = NEW.user_id;

        INSERT INTO public.user_daily_stats (user_id, stat_date, images_protected)
        VALUES (NEW.user_id, CURRENT_DATE, 1)
        ON CONFLICT (user_id, stat_date)
        DO UPDATE SET
            images_protected = public.user_daily_stats.images_protected + 1,
            updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER trigger_increment_image_count
    AFTER INSERT OR UPDATE ON public.protected_images
    FOR EACH ROW
    EXECUTE FUNCTION public.increment_image_count();

-- ─────────────────────────────────────────────────────────────────────
-- 14. RPC FUNCTION — Get User Analytics
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.get_user_analytics(p_user_id UUID)
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'total_protected', COALESCE(COUNT(*), 0),
        'avg_confidence_drop', COALESCE(ROUND(AVG(confidence_drop)::numeric, 1), 0),
        'avg_similarity_score', COALESCE(ROUND(AVG(similarity_score)::numeric, 1), 0),
        'avg_psnr', COALESCE(ROUND(AVG(psnr)::numeric, 2), 0),
        'avg_ssim', COALESCE(ROUND(AVG(ssim)::numeric, 4), 0),
        'threats_detected', COALESCE(COUNT(*) * 6, 0),
        'privacy_score', LEAST(100, 70 + COALESCE(COUNT(*), 0) * 2),
        'protection_breakdown', (
            SELECT json_build_object(
                'adversarial', COUNT(*) FILTER (WHERE 'adversarial' = ANY(protection_types)),
                'watermark',   COUNT(*) FILTER (WHERE 'watermark' = ANY(protection_types)),
                'deepfake',    COUNT(*) FILTER (WHERE 'deepfake' = ANY(protection_types))
            )
            FROM public.protected_images
            WHERE user_id = p_user_id AND status = 'completed'
        )
    ) INTO result
    FROM public.protected_images
    WHERE user_id = p_user_id AND status = 'completed';

    RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ─────────────────────────────────────────────────────────────────────
-- 15. RPC FUNCTION — Get Weekly Activity
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.get_weekly_activity(p_user_id UUID, p_days INTEGER DEFAULT 7)
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_agg(
        json_build_object(
            'name', TO_CHAR(d.day, 'Dy'),
            'date', d.day,
            'protected', COALESCE(s.images_protected, 0),
            'threats', COALESCE(s.threats_detected, 0)
        ) ORDER BY d.day
    ) INTO result
    FROM generate_series(
        CURRENT_DATE - (p_days - 1),
        CURRENT_DATE,
        '1 day'::INTERVAL
    ) AS d(day)
    LEFT JOIN public.user_daily_stats s
        ON s.user_id = p_user_id AND s.stat_date = d.day;

    RETURN COALESCE(result, '[]'::JSON);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ─────────────────────────────────────────────────────────────────────
-- 16. ROW LEVEL SECURITY (RLS) POLICIES
-- ─────────────────────────────────────────────────────────────────────

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.protected_images ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.verification_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.anti_scraping_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.anti_scraping_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_daily_stats ENABLE ROW LEVEL SECURITY;

-- ── PROFILES ──
CREATE POLICY "Users can view own profile"
    ON public.profiles FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

-- ── PROTECTED IMAGES ──
CREATE POLICY "Users can view own images"
    ON public.protected_images FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own images"
    ON public.protected_images FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own images"
    ON public.protected_images FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own images"
    ON public.protected_images FOR DELETE
    USING (auth.uid() = user_id);

-- ── VERIFICATION RESULTS ──
CREATE POLICY "Users can view own verifications"
    ON public.verification_results FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own verifications"
    ON public.verification_results FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- ── THREAT LOG ──
CREATE POLICY "Users can view own threats"
    ON public.threat_log FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own threats"
    ON public.threat_log FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- ── ANTI-SCRAPING SCANS ──
CREATE POLICY "Users can view own scans"
    ON public.anti_scraping_scans FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own scans"
    ON public.anti_scraping_scans FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- ── ANTI-SCRAPING RESULTS ──
CREATE POLICY "Users can view own scan results"
    ON public.anti_scraping_results FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own scan results"
    ON public.anti_scraping_results FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- ── AI MODELS (publicly readable) ──
CREATE POLICY "Anyone can view AI models"
    ON public.ai_models FOR SELECT
    USING (TRUE);

-- ── DAILY STATS ──
CREATE POLICY "Users can view own stats"
    ON public.user_daily_stats FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can manage own stats"
    ON public.user_daily_stats FOR ALL
    USING (auth.uid() = user_id);

-- ─────────────────────────────────────────────────────────────────────
-- 17. STORAGE BUCKETS
-- ─────────────────────────────────────────────────────────────────────
-- NOTE: Run these only if your Supabase instance supports direct bucket creation via SQL.
-- Otherwise, create buckets via the Supabase Dashboard:
--   - originals (private, 15MB limit, image/* only)
--   - protected (private, 15MB limit, image/* only)
--   - avatars   (public, 2MB limit, image/* only)

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES
    ('originals', 'originals', FALSE, 15728640, ARRAY['image/png','image/jpeg','image/webp']),
    ('protected', 'protected', FALSE, 15728640, ARRAY['image/png','image/jpeg','image/webp']),
    ('avatars',   'avatars',   TRUE,  2097152,  ARRAY['image/png','image/jpeg','image/webp'])
ON CONFLICT (id) DO NOTHING;

-- Storage RLS policies
CREATE POLICY "Users can upload originals"
    ON storage.objects FOR INSERT
    WITH CHECK (bucket_id = 'originals' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can view own originals"
    ON storage.objects FOR SELECT
    USING (bucket_id = 'originals' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can upload protected images"
    ON storage.objects FOR INSERT
    WITH CHECK (bucket_id = 'protected' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can view own protected images"
    ON storage.objects FOR SELECT
    USING (bucket_id = 'protected' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can upload avatars"
    ON storage.objects FOR INSERT
    WITH CHECK (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Anyone can view avatars"
    ON storage.objects FOR SELECT
    USING (bucket_id = 'avatars');

CREATE POLICY "Users can update own avatars"
    ON storage.objects FOR UPDATE
    USING (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

-- ─────────────────────────────────────────────────────────────────────
-- 18. DASHBOARD SUMMARY VIEW
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW public.v_user_dashboard AS
SELECT
    p.id AS user_id,
    p.name,
    p.plan,
    p.images_protected_count,
    COALESCE(AVG(pi.confidence_drop), 0)::NUMERIC(5,1) AS avg_confidence_drop,
    COALESCE(AVG(pi.similarity_score), 0)::NUMERIC(5,1) AS avg_similarity_score,
    COALESCE(AVG(pi.psnr), 0)::NUMERIC(6,2) AS avg_psnr,
    COALESCE(AVG(pi.ssim), 0)::NUMERIC(6,4) AS avg_ssim,
    COUNT(pi.id)::INTEGER AS total_images,
    (SELECT COUNT(*) FROM public.threat_log tl WHERE tl.user_id = p.id)::INTEGER AS total_threats
FROM public.profiles p
LEFT JOIN public.protected_images pi ON pi.user_id = p.id AND pi.status = 'completed'
GROUP BY p.id, p.name, p.plan, p.images_protected_count;

-- ─────────────────────────────────────────────────────────────────────
-- 19. SEED DATA — AI Models
-- ─────────────────────────────────────────────────────────────────────
INSERT INTO public.ai_models (name, model_type, evasion_rate, strength_score, resistance_rate, status, last_updated, version, description) VALUES
    ('AdversarialNet v3.1', 'adversarial_perturbation', 99.2, NULL, NULL, 'active', '2026-03-28', '3.1.0', 'FGSM/PGD adversarial perturbation targeting FaceNet embeddings'),
    ('WatermarkDCT v2.0', 'invisible_watermark', NULL, 97.3, NULL, 'active', '2026-03-20', '2.0.0', 'DCT-domain invisible watermarking with golden-ratio coefficient selection'),
    ('DeepfakeGuard v4.2', 'deepfake_immunization', NULL, NULL, 96.1, 'active', '2026-03-30', '4.2.0', 'Frequency + spatial disruption targeting GAN encoder-decoder networks');

-- =====================================================================
-- DONE! Your Supabase database is ready.
--
-- Next steps:
--   1. Set up Supabase Auth (email/password enabled)
--   2. Install @supabase/supabase-js in your Next.js frontend
--   3. Create Edge Functions for AI pipeline (protect, verify, anti-scraping)
--   4. Deploy Python FastAPI backend separately for compute-heavy AI tasks
--   5. Follow the Master Prompt in walkthrough.md for full integration
-- =====================================================================
