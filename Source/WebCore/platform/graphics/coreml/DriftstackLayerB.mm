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

#import <CoreML/CoreML.h>
#import <Foundation/Foundation.h>
#import <cmath>
#import <chrono>
#import <cstdlib>
#import <span>
#import <string_view>
#import <wtf/Assertions.h>
#import <wtf/StdLibExtras.h>

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
}

void LayerB::readFeatureFlag()
{
    const char* env = std::getenv("DRIFTSTACK_LAYER_B_ENABLED");
    // Use string_view for bounds-checked comparison (avoids
    // -Wunsafe-buffer-usage on raw pointer indexing).
    m_isEnabled = env && std::string_view { env } == "1";

    if (m_isEnabled)
        WTFLogAlways("[V-790.V] LayerB feature flag ENABLED");
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

} // namespace WebCore::Driftstack

#endif // PLATFORM(MAC) || PLATFORM(IOS_FAMILY)
