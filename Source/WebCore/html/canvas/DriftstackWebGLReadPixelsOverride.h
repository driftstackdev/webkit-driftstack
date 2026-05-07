/*
 * DriftstackWebGLReadPixelsOverride.h — V-375 (Gap 3 closure).
 *
 * WebGL readPixels substitution for canonical fingerprinting probe
 * shapes. Vendors using `WebGLRenderingContext.readPixels` to hash
 * GPU pixel output (browserleaks /webgl, FPJS WebGL hash, CreepJS
 * WebGL probe) bypass the V-185 toDataURL canvas-fp dispatch entirely
 * (per V-372 Gap 3 finding). V-375 closes that bypass.
 *
 * Phase classification (file 105):
 *   - Phase 2 (process-startup, lazy): base64 decode + cache of iPhone-
 *     captured RGBA byte buffers per (canvasWidth, canvasHeight,
 *     glFormat, glType) topology key.
 *   - Phase 3 (per-call): substitution dispatch at
 *     WebGLRenderingContextBase::readPixels entry, before the
 *     graphicsContextGL()->readPixels native call.
 *
 * Key shape: (canvasWidth, canvasHeight, glFormat, glType). Match
 * requires (x, y) == (0, 0) and rect spans the full drawing buffer
 * (sub-rect reads fall through to native; vendor probes always read
 * the full canvas).
 *
 * iPhone 16 Pro / iOS 18.6 reference (V-217 / Stage G era; V-375
 * extended with full pixelBytesBase64 capture):
 *   - 256×256 RGBA UNSIGNED_BYTE: G5 webgl-matrix probe — clearColor
 *     (0.1,0.4,0.7,1.0) + colored triangle, byte-deterministic
 *     across BS Automate sessions.
 *
 * Cross-codebase rationale (founder direction 2026-05-07):
 *   substitution-at-hook means fork never runs native GPU pixel
 *   readback when atlas hits → bit-identical iOS 18.6 reference
 *   output regardless of fork's WebKit 625.x ANGLE pipeline. WebGL
 *   pixel output is GPU-driver-specific (Mac Apple Silicon vs
 *   iPhone GPU produces different rasterization at triangle edges
 *   even with identical shaders); substitution is the correct
 *   architecture for bit-identical match.
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>
#include <span>

namespace WebCore {

struct WebGLReadPixelsOverrideEntry {
    const char* archetype;          // e.g. "iphone16pro_ios18_bs"
    const char* probeKey;           // e.g. "g5_triangle_clearcolor_256x256"
    uint32_t canvasWidth;
    uint32_t canvasHeight;
    uint32_t glFormat;              // GL_RGBA = 0x1908
    uint32_t glType;                // GL_UNSIGNED_BYTE = 0x1401
    uint32_t pixelByteCount;        // = w * h * bpp(format, type)
    const char* pixelBytesBase64;   // raw RGBA bytes, base64-encoded
};

namespace Driftstack {

// Process-startup gate. Reads DRIFTSTACK_WEBGL_READPIXELS_OVERRIDE
// env var once. Defaults off until founder explicitly authorizes.
bool isWebGLReadPixelsOverrideEnabled();

// V-375 entry: given (canvasWidth, canvasHeight, glFormat, glType),
// look up the matching iPhone-canonical row and lazy-decode its
// base64 pixel bytes. Returns true on hit; outBytes is a span over
// the cached buffer (lifetime is process). False on miss.
bool getWebGLReadPixelsOverrideBytes(uint32_t canvasWidth, uint32_t canvasHeight, uint32_t glFormat, uint32_t glType, std::span<const uint8_t>& outBytes);

} // namespace Driftstack
} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
