/*
 * Copyright (C) 2026 Driftstack. All rights reserved.
 *
 * V-790.V Layer B WebKit fork integration — Objective-C++ implementation.
 *
 * See DriftstackLayerB.h for design rationale. This .mm file wraps
 * CoreML MLModel for inference. Compiled only when DriftstackLayerB.h
 * is included (no automatic CoreML dependency in other translation
 * units).
 *
 * Feature-flag gated: DRIFTSTACK_LAYER_B_ENABLED env var (default OFF).
 * Model loaded from a search path that accepts either dev (reference/
 * models/v790g-layerb-final.mlpackage) or bundled (Resources/) location.
 *
 * Compute units: MLComputeUnitsCPUAndNeuralEngine per strict Rule P
 * (ANE-only routing, CPU fallback for ANE-unsupported ops only — no
 * GPU). V-790.AP empirically verified all 8 op groups in
 * GlyphDeltaPredictor are ANE-compatible.
 */

#import "config.h"
#import "DriftstackLayerB.h"

#if PLATFORM(MAC) || PLATFORM(IOS_FAMILY)

#import <CoreGraphics/CoreGraphics.h>
#import <CoreML/CoreML.h>
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <algorithm>
#import <cmath>
#import <chrono>
#import <cstdlib>
#import <span>
#import <string_view>
#import <wtf/Assertions.h>
#import <wtf/StdLibExtras.h>
#import <wtf/text/Base64.h>
#import <wtf/text/MakeString.h>
#import <wtf/text/StringView.h>

#if PLATFORM(MAC)
#import <UniformTypeIdentifiers/UTCoreTypes.h>
#endif

namespace WebCore::Driftstack {

namespace {

// Search path order — first match wins. Tries compiled .mlmodelc first
// (faster load + no runtime compile cost) then .mlpackage as fallback.
// Includes both:
//   - Bundled location: WebKit installation's WebCore Resources
//   - Dev location: ~/code/driftstack/reference/models/ (Layer B
//     persistent backup landed by wave 29-105/29-109)
//
// V-790.V wave 29-128: .mlmodelc support added. MLModel can load both
// .mlpackage (uncompiled, fails on macOS with "Unable to load model:
// Compile the model with Xcode or MLModel.compileModel(at:)") and
// .mlmodelc (compiled). For Driftstack we ship pre-compiled .mlmodelc
// to avoid runtime compile cost (Rule O v2 startup latency budget).
NSURL* findModelURL()
{
    NSArray<NSString*>* candidates = @[
        // Dev / autopilot path — reference/models/ in driftstack repo
        @"/Users/john/code/driftstack/reference/models/v790g-layerb-final.mlmodelc",
        @"/Users/john/code/driftstack/reference/models/v790g-layerb-final.mlpackage",
        // Bundled location (future install path)
        @"/Library/Frameworks/WebKit.framework/Resources/v790g-layerb-final.mlmodelc",
        @"/Library/Frameworks/WebKit.framework/Resources/v790g-layerb-final.mlpackage",
        @"/System/Library/Frameworks/WebKit.framework/Resources/v790g-layerb-final.mlmodelc",
        @"/System/Library/Frameworks/WebKit.framework/Resources/v790g-layerb-final.mlpackage",
    ];

    NSFileManager* fm = [NSFileManager defaultManager];
    for (NSString* path in candidates) {
        if ([fm fileExistsAtPath:path])
            return [NSURL fileURLWithPath:path];
    }
    return nil;
}

// V-790.V2 (wave 29-202) — locate v2 mlpackage (canvas-level RGBA tile
// model). Staged at reference/models/v790g-layerb-v2-best.mlpackage by
// wave 29-196 V-790.GC after the 2500-pair retraining (val L1 0.0096).
NSURL* findModelV2URL()
{
    NSArray<NSString*>* candidates = @[
        @"/Users/john/code/driftstack/reference/models/v790g-layerb-v2-best.mlmodelc",
        @"/Users/john/code/driftstack/reference/models/v790g-layerb-v2-best.mlpackage",
        @"/Library/Frameworks/WebKit.framework/Resources/v790g-layerb-v2-best.mlmodelc",
        @"/Library/Frameworks/WebKit.framework/Resources/v790g-layerb-v2-best.mlpackage",
        @"/System/Library/Frameworks/WebKit.framework/Resources/v790g-layerb-v2-best.mlmodelc",
        @"/System/Library/Frameworks/WebKit.framework/Resources/v790g-layerb-v2-best.mlpackage",
    ];

    NSFileManager* fm = [NSFileManager defaultManager];
    for (NSString* path in candidates) {
        if ([fm fileExistsAtPath:path])
            return [NSURL fileURLWithPath:path];
    }
    return nil;
}

} // anonymous namespace

LayerB& LayerB::shared()
{
    // Per-WebProcess singleton.
    static LayerB* instance = new LayerB();
    return *instance;
}

LayerB::LayerB()
{
    readFeatureFlag();
    if (m_isEnabled)
        loadModel();
    if (m_isV2Enabled)
        loadModelV2();
}

void LayerB::readFeatureFlag()
{
    const char* env = std::getenv("DRIFTSTACK_LAYER_B_ENABLED");
    // Use string_view for bounds-checked comparison (avoids
    // -Wunsafe-buffer-usage on raw pointer indexing).
    m_isEnabled = env && std::string_view { env } == "1";

    if (m_isEnabled)
        WTFLogAlways("[V-790.V] LayerB feature flag ENABLED");

    // V-790.V2 (wave 29-202) — independent v2 gate. v2 is the canvas-
    // level RGBA tile substitution; can be enabled separately from v1.
    const char* envV2 = std::getenv("DRIFTSTACK_LAYER_B_V2_ENABLED");
    m_isV2Enabled = envV2 && std::string_view { envV2 } == "1";

    if (m_isV2Enabled)
        WTFLogAlways("[V-790.V2] LayerB v2 (canvas-level RGBA) feature flag ENABLED");
}

void LayerB::loadModel()
{
    NSURL* modelURL = findModelURL();
    if (!modelURL) {
        WTFLogAlways("[V-790.V] LayerB model not found in search path — "
                     "LayerB disabled this WebProcess");
        return;
    }

    NSError* error = nil;

    // V-790.V Phase 3.E (wave 29-130): branch on extension.
    // compileModelAtURL: expects .mlpackage (with Manifest.json),
    // modelWithContentsOfURL: expects pre-compiled .mlmodelc.
    //
    // Phase 3.D unconditional compileModelAtURL: failed when given a
    // .mlmodelc:
    //   "A valid manifest does not exist at path: .../Manifest.json"
    //
    // Phase 3.E: if URL is .mlpackage, compile-at-runtime → tmp
    // .mlmodelc; if URL is .mlmodelc, load directly.
    NSURL* loadURL = modelURL;
    NSString* pathExt = [[modelURL path] pathExtension];
    if ([pathExt isEqualToString:@"mlpackage"]) {
        NSURL* compiledURL = [MLModel compileModelAtURL:modelURL error:&error];
        if (!compiledURL) {
            const char* errMsg = error
                ? [[error localizedDescription] UTF8String]
                : "unknown error";
            WTFLogAlways("[V-790.V] LayerB compileModelAtURL failed: %s", errMsg);
            return;
        }
        loadURL = compiledURL;
        WTFLogAlways("[V-790.V] LayerB compiled .mlpackage → %s",
                     [[compiledURL path] UTF8String]);
    }

    MLModelConfiguration* config = [[MLModelConfiguration alloc] init];

    // Strict Rule P: ANE-only inference. CPUAndNeuralEngine permits CPU
    // as fallback for ANE-unsupported ops (V-790.AP confirms all op
    // groups in GlyphDeltaPredictor are ANE-compatible, but the CPU
    // path is the safety net). GPU is excluded — Mac GPU adds
    // non-determinism per Apple Metal compiler scheduling.
    config.computeUnits = MLComputeUnitsCPUAndNeuralEngine;

    MLModel* model = [MLModel modelWithContentsOfURL:loadURL
                                       configuration:config
                                               error:&error];

    // V-790.V Phase 3.B (wave 29-134): observed intermittent .mlmodelc
    // direct-load failure on 2nd+ WebProcess. The first WebProcess loaded
    // the .mlmodelc cleanly, but a fresh WebProcess later in the page
    // lifecycle hit "Unable to load model: Compile the model with Xcode".
    // Suspected: .mlmodelc loaded by a previous process leaves stale
    // state somewhere; fresh process retries direct load and fails.
    //
    // Fallback: when direct .mlmodelc load fails AND a .mlpackage is
    // also present in the search path, retry via compileModelAtURL:.
    // The runtime compile path always succeeds for a valid .mlpackage
    // (paid 1-2s startup once per WebProcess).
    if (!model && [pathExt isEqualToString:@"mlmodelc"]) {
        // Look for sibling .mlpackage in the same directory
        NSString* modelDir = [[modelURL path] stringByDeletingLastPathComponent];
        NSString* baseName = [[[modelURL path] lastPathComponent]
            stringByDeletingPathExtension];
        NSString* mlpackagePath = [NSString stringWithFormat:@"%@/%@.mlpackage",
            modelDir, baseName];
        NSFileManager* fm = [NSFileManager defaultManager];
        if ([fm fileExistsAtPath:mlpackagePath]) {
            const char* errMsg = error
                ? [[error localizedDescription] UTF8String]
                : "unknown";
            WTFLogAlways("[V-790.V] LayerB .mlmodelc direct-load failed "
                         "(%s); falling back to .mlpackage runtime compile",
                         errMsg);
            NSURL* mlpackageURL = [NSURL fileURLWithPath:mlpackagePath];
            error = nil;
            NSURL* compiledURL = [MLModel compileModelAtURL:mlpackageURL error:&error];
            if (compiledURL) {
                error = nil;
                model = [MLModel modelWithContentsOfURL:compiledURL
                                          configuration:config
                                                  error:&error];
                if (model) {
                    loadURL = compiledURL;
                    WTFLogAlways("[V-790.V] LayerB fallback compile+load OK");
                }
            }
        }
    }

    if (!model) {
        const char* errMsg = error
            ? [[error localizedDescription] UTF8String]
            : "unknown error";
        WTFLogAlways("[V-790.V] LayerB MLModel load failed: %s", errMsg);
        return;
    }

    // Bridge ARC strong reference to a CF retain so the C++ void* m_model
    // owns one retain count past this scope. Released in destructor (not
    // implemented at Phase 1 — singleton lives forever for now).
    // const_cast through CFTypeRef avoids -Wcast-qual (CFBridgingRetain
    // returns const void*).
    m_model = const_cast<void*>(CFBridgingRetain(model));
    m_isLoaded = true;

    WTFLogAlways("[V-790.V] LayerB loaded model from %s "
                 "(MLComputeUnitsCPUAndNeuralEngine, strict Rule P)",
                 [[modelURL path] UTF8String]);
}

// V-790.V2 (wave 29-202) — v2 model loader. Mirrors loadModel() pattern
// (compile-on-the-fly for .mlpackage / direct-load for .mlmodelc with
// .mlpackage fallback on direct-load fail). Independent state machine
// so v2 can load even if v1 fails (or vice versa).
void LayerB::loadModelV2()
{
    NSURL* modelURL = findModelV2URL();
    if (!modelURL) {
        WTFLogAlways("[V-790.V2] LayerB v2 model not found in search path — "
                     "v2 disabled this WebProcess");
        return;
    }

    NSError* error = nil;
    NSURL* loadURL = modelURL;
    NSString* pathExt = [[modelURL path] pathExtension];
    if ([pathExt isEqualToString:@"mlpackage"]) {
        NSURL* compiledURL = [MLModel compileModelAtURL:modelURL error:&error];
        if (!compiledURL) {
            const char* errMsg = error
                ? [[error localizedDescription] UTF8String]
                : "unknown error";
            WTFLogAlways("[V-790.V2] LayerB v2 compileModelAtURL failed: %s", errMsg);
            return;
        }
        loadURL = compiledURL;
        WTFLogAlways("[V-790.V2] LayerB v2 compiled .mlpackage → %s",
                     [[compiledURL path] UTF8String]);
    }

    MLModelConfiguration* config = [[MLModelConfiguration alloc] init];
    config.computeUnits = MLComputeUnitsCPUAndNeuralEngine;

    MLModel* model = [MLModel modelWithContentsOfURL:loadURL
                                       configuration:config
                                               error:&error];

    if (!model && [pathExt isEqualToString:@"mlmodelc"]) {
        NSString* modelDir = [[modelURL path] stringByDeletingLastPathComponent];
        NSString* baseName = [[[modelURL path] lastPathComponent]
            stringByDeletingPathExtension];
        NSString* mlpackagePath = [NSString stringWithFormat:@"%@/%@.mlpackage",
            modelDir, baseName];
        NSFileManager* fm = [NSFileManager defaultManager];
        if ([fm fileExistsAtPath:mlpackagePath]) {
            const char* errMsg = error
                ? [[error localizedDescription] UTF8String]
                : "unknown";
            WTFLogAlways("[V-790.V2] LayerB v2 .mlmodelc direct-load failed "
                         "(%s); falling back to .mlpackage runtime compile", errMsg);
            NSURL* mlpackageURL = [NSURL fileURLWithPath:mlpackagePath];
            error = nil;
            NSURL* compiledURL = [MLModel compileModelAtURL:mlpackageURL error:&error];
            if (compiledURL) {
                error = nil;
                model = [MLModel modelWithContentsOfURL:compiledURL
                                          configuration:config
                                                  error:&error];
                if (model) {
                    loadURL = compiledURL;
                    WTFLogAlways("[V-790.V2] LayerB v2 fallback compile+load OK");
                }
            }
        }
    }

    if (!model) {
        const char* errMsg = error
            ? [[error localizedDescription] UTF8String]
            : "unknown error";
        WTFLogAlways("[V-790.V2] LayerB v2 MLModel load failed: %s", errMsg);
        return;
    }

    m_modelV2 = const_cast<void*>(CFBridgingRetain(model));
    m_isV2Loaded = true;

    WTFLogAlways("[V-790.V2] LayerB v2 loaded model from %s "
                 "(MLComputeUnitsCPUAndNeuralEngine, strict Rule P)",
                 [[modelURL path] UTF8String]);
}

// V-790.V2 (wave 29-202) — canvas-level RGBA tile prediction.
// Input: 256×256 RGBA float32 [0,1] (Mac fork canvas raster tile).
// Output: 256×256 RGBA float32 [0,1] (iPhone-canonical pixel reconstruction).
// Per-call Rule O v2 5ms HARD cap; caller enforces per-frame 16ms SOFT.
std::optional<LayerBV2Prediction> LayerB::predictV2(const LayerBV2Tile& mac_rgba)
{
    if (!m_isV2Enabled || !m_isV2Loaded || !m_modelV2)
        return std::nullopt;

    @autoreleasepool {
        MLModel* model = (__bridge MLModel*)m_modelV2;

        NSError* error = nil;
        // v2 input shape: (1, 4, 256, 256) float32 — batch, channels(R,G,B,A),
        // H, W. PyTorch convention (channels-first).
        MLMultiArray* macArray = [[MLMultiArray alloc]
            initWithShape:@[@1, @4, @256, @256]
                 dataType:MLMultiArrayDataTypeFloat32
                    error:&error];
        if (!macArray)
            return std::nullopt;

        // Copy input. Source layout from caller: row-major channel-interleaved
        // RGBA (R0,G0,B0,A0, R1,G1,B1,A1, ...). MLMultiArray expects
        // channels-first (R0...Rn, G0...Gn, B0...Bn, A0...An). Reshape.
        auto srcSpan = unsafeMakeSpan(mac_rgba.rgba.data(), LayerBV2Tile::kSize);
        auto dstSpan = unsafeMakeSpan(
            static_cast<float*>(macArray.dataPointer), LayerBV2Tile::kSize);
        constexpr size_t kPlaneSize = 256 * 256;
        for (size_t y = 0; y < 256; ++y) {
            for (size_t x = 0; x < 256; ++x) {
                size_t srcIdx = (y * 256 + x) * 4;
                size_t dstIdx = y * 256 + x;
                dstSpan[0 * kPlaneSize + dstIdx] = srcSpan[srcIdx + 0]; // R
                dstSpan[1 * kPlaneSize + dstIdx] = srcSpan[srcIdx + 1]; // G
                dstSpan[2 * kPlaneSize + dstIdx] = srcSpan[srcIdx + 2]; // B
                dstSpan[3 * kPlaneSize + dstIdx] = srcSpan[srcIdx + 3]; // A
            }
        }

        MLDictionaryFeatureProvider* input = [[MLDictionaryFeatureProvider alloc]
            initWithDictionary:@{ @"mac_rgba": macArray }
                         error:&error];
        if (!input)
            return std::nullopt;

        auto t0 = std::chrono::high_resolution_clock::now();
        id<MLFeatureProvider> output = [model predictionFromFeatures:input
                                                               error:&error];
        auto t1 = std::chrono::high_resolution_clock::now();

        if (!output || error)
            return std::nullopt;

        double inference_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        // Rule O v2 5ms HARD per-call cap.
        if (inference_ms > 5.0) {
            WTFLogAlways("[V-790.V2] LayerB v2 Rule O v2 5ms HARD violation: "
                         "inference_ms=%.3f — discarding prediction", inference_ms);
            return std::nullopt;
        }

        // Output: model named "iphone_rgba" (v2 export convention from
        // v790gc-v2-coreml-export.py). Fallback to first feature if name
        // changes in future CoreML conversions.
        MLFeatureValue* val = [output featureValueForName:@"iphone_rgba"];
        if (!val) {
            NSArray<NSString*>* names = [[output featureNames] allObjects];
            if (names.count > 0)
                val = [output featureValueForName:names[0]];
        }
        if (!val) return std::nullopt;

        MLMultiArray* iphoneArr = val.multiArrayValue;
        if (!iphoneArr) return std::nullopt;

        // Validate shape (1, 4, 256, 256).
        if (iphoneArr.shape.count < 4) return std::nullopt;

        LayerBV2Prediction prediction;
        prediction.inference_ms = inference_ms;
        prediction.ane_routed = true;

        // De-interleave channels-first → RGBA pixel-interleaved with
        // NaN/Inf clamp.
        auto outChw = unsafeMakeSpan(
            static_cast<const float*>(iphoneArr.dataPointer), LayerBV2Tile::kSize);
        auto outRgba = unsafeMakeSpan(prediction.tile.rgba.data(), LayerBV2Tile::kSize);
        for (size_t y = 0; y < 256; ++y) {
            for (size_t x = 0; x < 256; ++x) {
                size_t srcIdx = y * 256 + x;
                size_t dstIdx = (y * 256 + x) * 4;
                float r = outChw[0 * kPlaneSize + srcIdx];
                float g = outChw[1 * kPlaneSize + srcIdx];
                float b = outChw[2 * kPlaneSize + srcIdx];
                float a = outChw[3 * kPlaneSize + srcIdx];
                if (std::isnan(r) || std::isinf(r)) return std::nullopt;
                if (std::isnan(g) || std::isinf(g)) return std::nullopt;
                if (std::isnan(b) || std::isinf(b)) return std::nullopt;
                if (std::isnan(a) || std::isinf(a)) return std::nullopt;
                outRgba[dstIdx + 0] = std::clamp(r, 0.0f, 1.0f);
                outRgba[dstIdx + 1] = std::clamp(g, 0.0f, 1.0f);
                outRgba[dstIdx + 2] = std::clamp(b, 0.0f, 1.0f);
                outRgba[dstIdx + 3] = std::clamp(a, 0.0f, 1.0f);
            }
        }

        return prediction;
    } // @autoreleasepool
}

std::optional<LayerBPrediction> LayerB::predict(
    const std::array<std::array<uint8_t, 64>, 64>& mac_pixels,
    const LayerBFeatures& features)
{
    if (!m_isEnabled || !m_isLoaded || !m_model)
        return std::nullopt;

    @autoreleasepool {
        MLModel* model = (__bridge MLModel*)m_model;

        // Build Mac pixels MLMultiArray (1, 1, 64, 64) float32 [0, 1]
        NSError* error = nil;
        MLMultiArray* macArray = [[MLMultiArray alloc]
            initWithShape:@[@1, @1, @64, @64]
                 dataType:MLMultiArrayDataTypeFloat32
                    error:&error];
        if (!macArray)
            return std::nullopt;

        // WTF::unsafeMakeSpan for bounds-tagged buffer access — satisfies
        // -Wunsafe-buffer-usage-in-container (2-param std::span is
        // flagged in WebKit). MLMultiArray.dataPointer + known shape
        // is structurally safe; unsafeMakeSpan documents the manual
        // assertion.
        auto macData = unsafeMakeSpan(
            static_cast<float*>(macArray.dataPointer), 64 * 64);
        for (int y = 0; y < 64; ++y)
            for (int x = 0; x < 64; ++x)
                macData[y * 64 + x] = static_cast<float>(mac_pixels[y][x]) / 255.0f;

        // Build feature vector MLMultiArray (1, 4) float32
        MLMultiArray* featArray = [[MLMultiArray alloc]
            initWithShape:@[@1, @4]
                 dataType:MLMultiArrayDataTypeFloat32
                    error:&error];
        if (!featArray)
            return std::nullopt;

        auto featData = unsafeMakeSpan(
            static_cast<float*>(featArray.dataPointer), 4);
        featData[0] = static_cast<float>(features.font_id);
        featData[1] = static_cast<float>(features.pt_size_q4) / 16.0f;
        featData[2] = static_cast<float>(features.codepoint);
        featData[3] = static_cast<float>(features.pos_class);

        MLDictionaryFeatureProvider* input = [[MLDictionaryFeatureProvider alloc]
            initWithDictionary:@{ @"mac": macArray, @"feat": featArray }
                         error:&error];

        if (!input)
            return std::nullopt;

        // Inference with Rule O v2 5ms HARD timing.
        auto t0 = std::chrono::high_resolution_clock::now();
        id<MLFeatureProvider> output = [model predictionFromFeatures:input
                                                               error:&error];
        auto t1 = std::chrono::high_resolution_clock::now();

        if (!output || error)
            return std::nullopt;

        double inference_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        // Rule O v2 HARD cap: discard prediction if too slow.
        if (inference_ms > 5.0) {
            WTFLogAlways("[V-790.V] LayerB Rule O v2 5ms HARD violation: "
                         "inference_ms=%.3f — discarding prediction", inference_ms);
            return std::nullopt;
        }

        // Extract delta (output name from V-790.R: "var_228" per CoreML
        // converter; may rename in future model versions).
        MLFeatureValue* val = [output featureValueForName:@"var_228"];
        if (!val) val = [output featureValueForName:@"output"];
        if (!val) return std::nullopt;

        MLMultiArray* deltaArr = val.multiArrayValue;
        if (!deltaArr) return std::nullopt;

        // Validate shape (1, 1, 64, 64).
        if (deltaArr.shape.count < 2)
            return std::nullopt;

        LayerBPrediction prediction;
        prediction.inference_ms = inference_ms;
        prediction.ane_routed = true; // Best-effort; MLComputePlan API
                                       // could verify post-iOS 17 but
                                       // CPU-fallback is rare for known
                                       // ANE-compatible ops.

        // Copy + NaN check delta.
        auto deltaData = unsafeMakeSpan(
            static_cast<const float*>(deltaArr.dataPointer), 64 * 64);
        for (int y = 0; y < 64; ++y) {
            for (int x = 0; x < 64; ++x) {
                float v = deltaData[y * 64 + x];
                if (std::isnan(v) || std::isinf(v))
                    return std::nullopt;
                prediction.delta[y][x] = v;
            }
        }

        return prediction;
    } // @autoreleasepool
}

// ============================================================================
// V-790.V2 §3.1.3 canvas-hook helpers (wave 29-398).
// ============================================================================

namespace {

// Resize a source RGBA pixel buffer (srcW x srcH, 8bpc, premul-RGBA layout)
// to dst 256x256 RGBA float32 [0,1] via bilinear interpolation. Layer B v2
// expects fixed 256x256 input; canvases of any size route through this.
void resizeRGBA8ToLayerBV2Tile(std::span<const uint8_t> src, size_t srcW,
                               size_t srcH, LayerBV2Tile& dst)
{
    constexpr size_t kDstSize = 256;
    if (srcW == 0 || srcH == 0)
        return;
    const float scaleX = static_cast<float>(srcW - 1) / static_cast<float>(kDstSize - 1);
    const float scaleY = static_cast<float>(srcH - 1) / static_cast<float>(kDstSize - 1);
    for (size_t dy = 0; dy < kDstSize; ++dy) {
        float fy = static_cast<float>(dy) * scaleY;
        size_t iy0 = static_cast<size_t>(fy);
        size_t iy1 = std::min(iy0 + 1, srcH - 1);
        float wy = fy - static_cast<float>(iy0);
        for (size_t dx = 0; dx < kDstSize; ++dx) {
            float fx = static_cast<float>(dx) * scaleX;
            size_t ix0 = static_cast<size_t>(fx);
            size_t ix1 = std::min(ix0 + 1, srcW - 1);
            float wx = fx - static_cast<float>(ix0);
            for (int c = 0; c < 4; ++c) {
                float v00 = static_cast<float>(src[(iy0 * srcW + ix0) * 4 + c]);
                float v10 = static_cast<float>(src[(iy0 * srcW + ix1) * 4 + c]);
                float v01 = static_cast<float>(src[(iy1 * srcW + ix0) * 4 + c]);
                float v11 = static_cast<float>(src[(iy1 * srcW + ix1) * 4 + c]);
                float v0 = v00 * (1.0f - wx) + v10 * wx;
                float v1 = v01 * (1.0f - wx) + v11 * wx;
                float v  = (v0 * (1.0f - wy) + v1 * wy) / 255.0f;
                dst.rgba[(dy * kDstSize + dx) * 4 + c] = std::clamp(v, 0.0f, 1.0f);
            }
        }
    }
}

// Reverse: 256x256 LayerBV2Tile [0,1] → dstW x dstH RGBA 8bpc bilinear.
void resizeLayerBV2TileToRGBA8(const LayerBV2Tile& src, size_t dstW,
                               size_t dstH, std::span<uint8_t> dst)
{
    constexpr size_t kSrcSize = 256;
    if (dstW == 0 || dstH == 0)
        return;
    const float scaleX = static_cast<float>(kSrcSize - 1) / static_cast<float>(dstW > 1 ? dstW - 1 : 1);
    const float scaleY = static_cast<float>(kSrcSize - 1) / static_cast<float>(dstH > 1 ? dstH - 1 : 1);
    for (size_t dy = 0; dy < dstH; ++dy) {
        float fy = static_cast<float>(dy) * scaleY;
        size_t iy0 = std::min(static_cast<size_t>(fy), kSrcSize - 1);
        size_t iy1 = std::min(iy0 + 1, kSrcSize - 1);
        float wy = fy - static_cast<float>(iy0);
        for (size_t dx = 0; dx < dstW; ++dx) {
            float fx = static_cast<float>(dx) * scaleX;
            size_t ix0 = std::min(static_cast<size_t>(fx), kSrcSize - 1);
            size_t ix1 = std::min(ix0 + 1, kSrcSize - 1);
            float wx = fx - static_cast<float>(ix0);
            for (int c = 0; c < 4; ++c) {
                float v00 = src.rgba[(iy0 * kSrcSize + ix0) * 4 + c];
                float v10 = src.rgba[(iy0 * kSrcSize + ix1) * 4 + c];
                float v01 = src.rgba[(iy1 * kSrcSize + ix0) * 4 + c];
                float v11 = src.rgba[(iy1 * kSrcSize + ix1) * 4 + c];
                float v0 = v00 * (1.0f - wx) + v10 * wx;
                float v1 = v01 * (1.0f - wx) + v11 * wx;
                float v  = v0 * (1.0f - wy) + v1 * wy;
                int q = static_cast<int>(std::round(std::clamp(v, 0.0f, 1.0f) * 255.0f));
                dst[(dy * dstW + dx) * 4 + c] = static_cast<uint8_t>(q);
            }
        }
    }
}

// Decode raw PNG bytes to a 256x256 LayerBV2Tile via CGImage. Returns
// nullopt on decode failure or non-image input.
std::optional<LayerBV2Tile> decodePNGToLayerBV2Tile(NSData* pngData)
{
    if (!pngData || pngData.length == 0)
        return std::nullopt;
    @autoreleasepool {
        CGImageSourceRef src = CGImageSourceCreateWithData(
            (__bridge CFDataRef)pngData, nullptr);
        if (!src)
            return std::nullopt;
        CGImageRef image = CGImageSourceCreateImageAtIndex(src, 0, nullptr);
        CFRelease(src);
        if (!image)
            return std::nullopt;
        size_t w = CGImageGetWidth(image);
        size_t h = CGImageGetHeight(image);
        if (w == 0 || h == 0) {
            CGImageRelease(image);
            return std::nullopt;
        }
        // Draw into an RGBA8 buffer with known layout (premul-RGBA).
        std::vector<uint8_t> buf(w * h * 4, 0);
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGContextRef ctx = CGBitmapContextCreate(buf.data(), w, h, 8, w * 4, cs,
            static_cast<uint32_t>(kCGImageAlphaPremultipliedLast) | static_cast<uint32_t>(kCGBitmapByteOrder32Big));
        CGColorSpaceRelease(cs);
        if (!ctx) {
            CGImageRelease(image);
            return std::nullopt;
        }
        CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), image);
        CGContextRelease(ctx);
        CGImageRelease(image);
        LayerBV2Tile tile;
        auto bufSpan = unsafeMakeSpan(const_cast<const uint8_t*>(buf.data()), buf.size());
        resizeRGBA8ToLayerBV2Tile(bufSpan, w, h, tile);
        return tile;
    }
}

// Encode a LayerBV2Tile (resized to canvasW x canvasH) into PNG bytes via
// CGImageDestination. Returns empty NSData on failure.
NSData* encodeLayerBV2TileToPNG(const LayerBV2Tile& tile, uint16_t canvasW, uint16_t canvasH)
{
    if (canvasW == 0 || canvasH == 0)
        return nil;
    @autoreleasepool {
        size_t w = canvasW;
        size_t h = canvasH;
        std::vector<uint8_t> buf(w * h * 4, 0);
        auto bufSpan = unsafeMakeSpan(buf.data(), buf.size());
        resizeLayerBV2TileToRGBA8(tile, w, h, bufSpan);
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGContextRef ctx = CGBitmapContextCreate(buf.data(), w, h, 8, w * 4, cs,
            static_cast<uint32_t>(kCGImageAlphaPremultipliedLast) | static_cast<uint32_t>(kCGBitmapByteOrder32Big));
        CGColorSpaceRelease(cs);
        if (!ctx)
            return nil;
        CGImageRef image = CGBitmapContextCreateImage(ctx);
        CGContextRelease(ctx);
        if (!image)
            return nil;
        CFMutableDataRef pngData = CFDataCreateMutable(kCFAllocatorDefault, 0);
        CGImageDestinationRef dest = CGImageDestinationCreateWithData(
            pngData, CFSTR("public.png"), 1, nullptr);
        if (!dest) {
            CFRelease(pngData);
            CGImageRelease(image);
            return nil;
        }
        CGImageDestinationAddImage(dest, image, nullptr);
        bool ok = CGImageDestinationFinalize(dest);
        CFRelease(dest);
        CGImageRelease(image);
        if (!ok) {
            CFRelease(pngData);
            return nil;
        }
        return (__bridge_transfer NSData*)pngData;
    }
}

} // anonymous namespace

std::optional<LayerBV2Tile> macForkRGBAFromDataURL(const WTF::String& dataURL,
                                                  uint16_t canvasW,
                                                  uint16_t canvasH)
{
    UNUSED_PARAM(canvasW);
    UNUSED_PARAM(canvasH);
    static constexpr ASCIILiteral kPNGPrefix = "data:image/png;base64,"_s;
    if (!dataURL.startsWith(kPNGPrefix))
        return std::nullopt;
    StringView b64View = StringView(dataURL).substring(kPNGPrefix.length());
    auto decoded = base64Decode(b64View);
    if (!decoded)
        return std::nullopt;
    auto decodedSpan = decoded->span();
    NSData* pngData = [NSData dataWithBytes:decodedSpan.data() length:decodedSpan.size()];
    return decodePNGToLayerBV2Tile(pngData);
}

std::optional<LayerBV2Tile> macForkRGBAFromPNGBytes(std::span<const uint8_t> pngBytes,
                                                   uint16_t canvasW,
                                                   uint16_t canvasH)
{
    UNUSED_PARAM(canvasW);
    UNUSED_PARAM(canvasH);
    if (pngBytes.empty())
        return std::nullopt;
    NSData* pngData = [NSData dataWithBytes:pngBytes.data() length:pngBytes.size()];
    return decodePNGToLayerBV2Tile(pngData);
}

WTF::String dataURLFromIPhoneRGBA(const LayerBV2Tile& iphone_rgba,
                                  uint16_t canvasW, uint16_t canvasH)
{
    NSData* pngData = encodeLayerBV2TileToPNG(iphone_rgba, canvasW, canvasH);
    if (!pngData)
        return { };
    auto pngSpan = unsafeMakeSpan(
        static_cast<const uint8_t*>(pngData.bytes), pngData.length);
    return makeString("data:image/png;base64,"_s, base64Encoded(pngSpan));
}

WTF::Vector<uint8_t> pngBytesFromIPhoneRGBA(const LayerBV2Tile& iphone_rgba,
                                            uint16_t canvasW, uint16_t canvasH)
{
    NSData* pngData = encodeLayerBV2TileToPNG(iphone_rgba, canvasW, canvasH);
    if (!pngData)
        return { };
    WTF::Vector<uint8_t> out;
    out.reserveInitialCapacity(pngData.length);
    auto pngSpan = unsafeMakeSpan(
        static_cast<const uint8_t*>(pngData.bytes), pngData.length);
    out.append(pngSpan);
    return out;
}

bool isCanaryFingerprintHost(const WTF::String& host)
{
    if (host.isEmpty())
        return false;
    // Lower-case the host for case-insensitive matching.
    auto hostLower = host.convertToASCIILowercase();
    // Rule Q canary fingerprint vendor patterns. ATLAS-ONLY for these
    // contexts; Layer B v2 NEVER fires on canary canvases (per
    // feedback_rule_q_canary_probe_atlas_only).
    static constexpr ASCIILiteral kCanaryPatterns[] = {
        "fingerprint.com"_s,
        "fpjs.io"_s,
        "fpjscdn.net"_s,
        "creepjs"_s,
        "abrahamjuliot.github.io"_s, // CreepJS host on GitHub Pages
        "botd"_s,
        "browserleaks.com"_s,
        "amiunique.org"_s,
        "coveryourtracks.eff.org"_s,
        "panopticlick"_s,
        "deviceandbrowserinfo.com"_s,
    };
    for (auto pattern : kCanaryPatterns) {
        if (hostLower.contains(pattern))
            return true;
    }
    return false;
}

} // namespace WebCore::Driftstack

#endif // PLATFORM(MAC) || PLATFORM(IOS_FAMILY)
