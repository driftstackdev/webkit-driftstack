/*
 * V-770.A.1 — DriftstackTextRunAtlas scaffold impl.
 *
 * v1: empty atlas, lookup() always returns nullopt. Helpers compute
 * text-run hash + position class + font ID mapping.
 */
#include "config.h"
#include "DriftstackTextRunAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include "Font.h"
#include "FloatPoint.h"
#include <wtf/text/CString.h>
#include <wtf/text/StringHasher.h>
#include <cmath>

namespace WebCore {

DriftstackTextRunAtlas& DriftstackTextRunAtlas::singleton()
{
    static DriftstackTextRunAtlas instance;
    return instance;
}

std::optional<DriftstackTextRunAtlasEntry> DriftstackTextRunAtlas::lookup(
    uint16_t /*fontId*/,
    uint16_t /*ptSize*/,
    uint8_t /*positionClass*/,
    uint64_t /*textRunHash*/)
{
    m_lookupCount++;
    // v1 stub: no atlas loaded; always miss.
    // V-770.B atlas builder produces the DSCFA2 binary; subsequent V-770.A.2
    // sub-slice will mmap the binary + implement actual lookup. For now,
    // returning nullopt means the V-771 hook's atlas-miss path is always
    // taken — proves the hook wiring is healthy + emits V-820.A telemetry.
    m_missCount++;
    return std::nullopt;
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
uint64_t driftstackComputeTextRunHash(
    const Font& font,
    std::span<const uint16_t> glyphs,
    std::span<const CGSize> advances)
{
    // FNV-1a 64-bit on (font_pointer, glyphs, advances). Glyph buffer is a
    // deterministic transform of (text, font, ptSize), so hashing it
    // captures text-run identity without needing the original string.
    //
    // Using font's pointer as the family discriminator is process-local
    // (different sessions get different pointer values), which is FINE for
    // atlas lookup since the atlas binary's font_id is the family id (mapped
    // via driftstackMapFontToId), not the runtime pointer. The hash here is
    // a high-entropy fingerprint for text-run-IDENTITY only — the (fontId,
    // ptSize, positionClass) tuple disambiguates per-archetype atlas slots.

    constexpr uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
    constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;

    uint64_t h = FNV_OFFSET;
    auto mixBytes = [&](const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            h ^= p[i];
            h *= FNV_PRIME;
        }
    };

    // Mix in font identity (use platform data postScriptName via Font ref).
    // Font is not directly stringifiable here; use the pointer's low 32 bits
    // as a discriminator (deterministic per session). The atlas builder will
    // canonicalize via Postscript name on the capture side.
    uintptr_t fontPtrVal = reinterpret_cast<uintptr_t>(&font);
    mixBytes(reinterpret_cast<const uint8_t*>(&fontPtrVal), sizeof(fontPtrVal));

    // Mix in glyphs.
    if (!glyphs.empty())
        mixBytes(reinterpret_cast<const uint8_t*>(glyphs.data()), glyphs.size() * sizeof(uint16_t));

    // Mix in advances (CGSize is 2× double = 16 bytes per).
    if (!advances.empty())
        mixBytes(reinterpret_cast<const uint8_t*>(advances.data()), advances.size() * sizeof(CGSize));

    return h;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

uint8_t driftstackComputePositionClass(CGContextRef cgContext, const FloatPoint& anchor)
{
    if (!cgContext)
        return 0;

    // 16x16 subpixel-offset grid: device-space (xFrac, yFrac) ∈ [0, 1)² → 8-bit class.
    CGAffineTransform ctm = CGContextGetCTM(cgContext);
    CGPoint device = CGPointApplyAffineTransform(CGPointMake(anchor.x(), anchor.y()), ctm);

    double xFrac = device.x - std::floor(device.x);
    double yFrac = device.y - std::floor(device.y);

    // Clamp to [0, 15] (handle xFrac == 1.0 edge case via std::min).
    int xBin = static_cast<int>(std::floor(xFrac * 16.0));
    int yBin = static_cast<int>(std::floor(yFrac * 16.0));
    if (xBin > 15) xBin = 15;
    if (yBin > 15) yBin = 15;
    if (xBin < 0) xBin = 0;
    if (yBin < 0) yBin = 0;

    return static_cast<uint8_t>((yBin << 4) | xBin);
}

uint16_t driftstackMapFontToId(const Font& font)
{
    // v1 stub: returns 0 (unknown font). V-770.A.2 will use the font's
    // postscript name to look up against FONT_IDS table loaded from atlas
    // binary header. For now, 0 is fine since lookup() always returns
    // nullopt anyway.
    UNUSED_PARAM(font);
    return 0;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
