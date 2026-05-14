/*
 * Copyright (C) 2026 Driftstack. All rights reserved.
 *
 * V-790.V Layer B WebKit fork integration — public interface.
 *
 * Layer B is the ML delta predictor in the canvas-fp closure chain:
 *
 *   Layer A (text-run atlas) miss → Layer B (this) → Layer C BS oracle → Mac CT raster
 *
 * Layer B takes Mac CG-rasterized 64x64 pixels for a glyph run +
 * features (font_id, pt_size, codepoint, position class) and predicts
 * the iOS-vs-Mac pixel delta. Applying the delta to Mac pixels
 * produces iOS-equivalent output without per-shape atlas coverage.
 *
 * Per Rule N v2: Layer B is the "any-website" closure mechanism
 * (vs Layer A's enumerated-canonical-probe closure).
 *
 * Per Rule O v2: per-call HARD ≤ 5ms latency. V-790.G ep40 model
 * empirically delivers p95=0.22ms via CoreML/ANE (22x headroom).
 *
 * Per Rule P: ANE-only inference (MLComputeUnitsCPUAndNeuralEngine).
 *
 * Per Rule Q: canary fingerprint probe contexts ROUTE TO ATLAS ONLY
 * — Layer B inference is bypassed for known fingerprint-vendor
 * scripts to keep canonical-probe coverage deterministic.
 *
 * Activation: this module is feature-flag gated by env var
 * DRIFTSTACK_LAYER_B_ENABLED=1. Default OFF — module compiles but
 * stays inert until explicitly enabled. Hook integration into
 * FontCascadeCoreText::drawGlyphBuffer() is gated by the same flag.
 */

#pragma once

#if PLATFORM(MAC) || PLATFORM(IOS_FAMILY)

#include <array>
#include <cstdint>
#include <optional>
#include <wtf/Noncopyable.h>

namespace WebCore::Driftstack {

// Feature tuple consumed by the model alongside Mac pixels.
struct LayerBFeatures {
    uint16_t font_id { 0 };       // V-770 FONT_IDS table index
    uint16_t pt_size_q4 { 0 };    // ptSize × 16 (Q.4 fixed-point)
    uint32_t codepoint { 0 };     // First glyph codepoint of the run
    uint8_t  pos_class { 0 };     // (yFrac<<4 | xFrac) 16x16 bin
};

// Prediction output: 64x64 delta image + latency telemetry.
struct LayerBPrediction {
    // Per-pixel ios-vs-mac delta, range [-1.0, +1.0] in normalised
    // alpha space. Apply: ios_pixel = clamp01(mac_pixel/255.0 + delta) * 255
    std::array<std::array<float, 64>, 64> delta {};

    // CoreML predict call wall time (Rule O v2 metric).
    double inference_ms { 0.0 };

    // Was ANE actually used by CoreML scheduler (vs CPU fallback)?
    // Reported via MLComputePlan when available.
    bool ane_routed { false };
};

// V-790.V2 (wave 29-202) — canvas-level RGBA tile prediction.
// Input/output: 256x256 RGBA float32 in [0,1], row-major, channel-
// interleaved (4 channels). v2 hook substitutes at HTMLCanvasElement::
// toDataURL pre-encode rather than per-glyph in FontCascade. Closes
// the "any canvas test from any site" universal coverage gap that
// the per-glyph v1 hook didn't address (only fixed glyph alpha bits,
// not arbitrary canvas RGBA).
//
// 256x256 chosen for ANE-friendly layout + training tractability.
// Larger canvases tile with overlap; smaller canvases pad with
// transparent and crop result.
struct LayerBV2Tile {
    // 256 × 256 × 4 (RGBA) × 4 bytes (float) = 1 MiB. Held in
    // std::array so layout is contiguous + stack-allocatable for
    // single-tile cases.
    static constexpr size_t kSize = 256 * 256 * 4;
    std::array<float, kSize> rgba {};
};

struct LayerBV2Prediction {
    LayerBV2Tile tile {};
    double inference_ms { 0.0 };
    bool ane_routed { false };
};

class LayerB {
    WTF_MAKE_NONCOPYABLE(LayerB);
public:
    // Per-WebProcess singleton. Lazy-initialised on first access.
    static LayerB& shared();

    // v1 — per-glyph 64x64 alpha mask substitution (FontCascade hook).
    // Returns nullopt if (a) model not loaded, (b) feature flag disabled,
    // (c) inference latency exceeded Rule O v2 5ms HARD, or (d) any
    // numerical error (NaN/inf in delta).
    std::optional<LayerBPrediction> predict(
        const std::array<std::array<uint8_t, 64>, 64>& mac_pixels,
        const LayerBFeatures& features);

    // v2 — canvas-level 256x256 RGBA tile prediction (toDataURL hook).
    // Returns nullopt on same failure modes as v1. Per-call ≤5ms HARD;
    // caller's responsibility to enforce per-frame ≤16ms SOFT across
    // multiple tile predictions in a single render.
    std::optional<LayerBV2Prediction> predictV2(const LayerBV2Tile& mac_rgba);

    bool isLoaded() const { return m_isLoaded; }
    bool isEnabled() const { return m_isEnabled; }
    bool isV2Loaded() const { return m_isV2Loaded; }
    bool isV2Enabled() const { return m_isV2Enabled; }

private:
    LayerB();

    // Read DRIFTSTACK_LAYER_B_ENABLED and DRIFTSTACK_LAYER_B_V2_ENABLED.
    void readFeatureFlag();

    // Load v1 v790g-layerb-final.mlpackage (per-glyph alpha).
    void loadModel();

    // Load v2 v790g-layerb-v2-best.mlpackage (canvas-level RGBA).
    void loadModelV2();

    bool m_isEnabled { false };
    bool m_isLoaded { false };
    bool m_isV2Enabled { false };
    bool m_isV2Loaded { false };

    // Opaque CoreML MLModel* held in the .mm impl. void* in the header
    // to keep this file pure C++.
    void* m_model { nullptr };
    void* m_modelV2 { nullptr };
};

} // namespace WebCore::Driftstack

#endif // PLATFORM(MAC) || PLATFORM(IOS_FAMILY)
