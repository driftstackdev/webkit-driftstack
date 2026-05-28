/*
 * DriftstackCanvasFingerprint10xRGBA.h — V-373 (Gap 1 closure).
 *
 * Companion to DriftstackCanvasFingerprint10xOverride.h. The override
 * header stores iPhone-canonical canvas dataURLs as base64 PNG strings
 * for V-185/V-241 toDataURL substitution. V-373 widens dispatch to
 * CanvasRenderingContext2DBase::getImageData by lazily decoding each
 * referenced dataURL to non-premultiplied RGBA at first lookup and
 * caching the buffer for subsequent calls.
 *
 * Phase classification (file 105):
 *   - Phase 2 (process-startup, lazy): RGBA decode + cache
 *   - Phase 3 (per-call): substitution at getImageData entry
 *
 * Lossless-ness rationale: iPhone Safari's getImageData unpremultiplies
 * the canvas backing store; iPhone Safari's toDataURL+PNG-encode also
 * unpremultiplies before encoding. Both use the same CG unpremultiply
 * formula. Round-tripping our captured PNG through CG bitmap-context
 * premultiplied → manual unpremultiply produces output bit-equivalent
 * to what iPhone's getImageData would have returned.
 *
 * The dispatch keys (canvas width, height, lastFillText) match V-185's
 * lookup so the same 574-row override table covers both readback paths.
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>
#include <span>
#include <wtf/Vector.h>

namespace WTF {
class String;
}

namespace WebCore {
namespace Driftstack {

// Process-startup gate. Mirrors V-185's `s_canvasFp10xOverrideEnabled`
// in HTMLCanvasElement.cpp. Reads `DRIFTSTACK_CANVAS_FP10X_OVERRIDE`
// env var once.
bool isCanvasFp10xOverrideEnabled();

// V-373 entry: given a canvas's (width, height, lastFillText), look up
// the matching iPhone-canonical override row, lazily decode its PNG to
// non-premultiplied RGBA, and return the buffer. Returns true on hit;
// outRGBA spans the cached buffer (lifetime is the process).
bool getCanvasFp10xRGBAForCanvasState(int width, int height, const WTF::String& lastFillText, std::span<const uint8_t>& outRGBA);

// Wave 29-349: public wrapper for V-510 atlas lookup (HTMLCanvasElement.cpp's
// anon-namespace v510AtlasLookup is internally linked). Lets cross-TU callers
// (OffscreenCanvas::convertToBlob, HTMLCanvasElement::toBlob) substitute via
// V-510 atlas when probe doesn't match a V-241 canonical shape entry.
WTF::String v510AtlasLookupPublic(const WTF::String& macForkDataURL, const WTF::String& opSequenceSHA256Hex);

// Task #8 (2026-05-28): getImageData serve from the V-510 auto-learn atlas.
// Looks up the V-510 atlas (incl. the §4 priority slot) by op-sequence sha;
// on hit, decodes the iPhone-canonical PNG to non-premultiplied RGBA copied
// into outRGBA (caller-owned — no dangling span). Returns true on a
// dimension-matching hit. Lets getImageData serve the same bit-identical
// bytes toDataURL/toBlob already do (toDataURL↔getImageData cross-context
// coherence). Gated caller-side via DRIFTSTACK_GETIMAGEDATA_ATLAS.
bool getV510AtlasRGBAForOpSeq(const WTF::String& opSequenceSHA256Hex, int width, int height, WTF::Vector<uint8_t>& outRGBA);

} // namespace Driftstack
} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
