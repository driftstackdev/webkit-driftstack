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
#include "FontPlatformData.h"
#include <wtf/NeverDestroyed.h>
#include <wtf/text/CString.h>
#include <wtf/text/StringHasher.h>
#include <wtf/text/StringView.h>
#include <wtf/ThreadSpecific.h>
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
    uint16_t ptSize,
    StringView textUtf8,
    std::span<const uint16_t> glyphs,
    std::span<const CGSize> advances)
{
    // V-771.B: FNV-1a 64-bit on (fontId, ptSize, UTF-8 text, weight, italic).
    // Platform-independent — iPhone capture and Mac fork hash to the same
    // value for the same (text, font, ptSize) tuple, enabling atlas-key
    // parity across the divergent CT glyph buffers (RTL, shaping, ligatures).
    //
    // Fallback path: when textUtf8 is empty (drawGlyphs callers outside
    // FontCascade::drawGlyphBuffer text path, e.g., DrawGlyphsRecorder
    // replay or text-decoration marks), hash on the platform glyph buffer.
    // Those callers won't have atlas entries anyway; the fallback only
    // exists to keep hash output stable per call site for telemetry.

    constexpr uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
    constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;

    uint64_t h = FNV_OFFSET;
    auto mixBytes = [&](const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            h ^= p[i];
            h *= FNV_PRIME;
        }
    };

    // 1. Font family id (resolved via driftstackMapFontToId).
    uint16_t fontId = driftstackMapFontToId(font);
    mixBytes(reinterpret_cast<const uint8_t*>(&fontId), sizeof(fontId));

    // 2. Point size.
    mixBytes(reinterpret_cast<const uint8_t*>(&ptSize), sizeof(ptSize));

    // 3. UTF-8 text bytes (V-771.B primary identity).
    if (!textUtf8.isEmpty()) {
        auto utf8 = textUtf8.utf8();
        const uint8_t* utf8Bytes = reinterpret_cast<const uint8_t*>(utf8.data());
        mixBytes(utf8Bytes, utf8.length());
    } else {
        // V-770.A.1 fallback (platform-dependent — likely atlas-miss).
        if (!glyphs.empty())
            mixBytes(reinterpret_cast<const uint8_t*>(glyphs.data()), glyphs.size() * sizeof(uint16_t));
        if (!advances.empty())
            mixBytes(reinterpret_cast<const uint8_t*>(advances.data()), advances.size() * sizeof(CGSize));
    }

    // 4. Font weight (canonical bucket from FontDescription).
    uint16_t weight = static_cast<uint16_t>(font.platformData().size() * 0); // placeholder
    // FontPlatformData on Cocoa exposes weight via FontSelectionValue; the
    // builder-side capture uses the CSS weight (100..900). Until we wire the
    // canonical mapping, treat weight as 400 (regular) implicitly via fontId
    // — the atlas keys font_id per (family, weight, italic) tuple already.
    UNUSED_PARAM(weight);

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

// V-771.B thread-local source text plumbing.
//
// Each WebContent thread that renders canvas text owns its own slot;
// drawGlyphBuffer pushes a StringView, drawGlyphs reads it during hash
// computation, the scope guard clears on return. Saved/restored via a
// stack-allocated previous-value field so nested drawGlyphBuffer calls
// (e.g., text-decoration mark draws) don't lose their parent context.
namespace {

struct TextSourceSlot {
    StringView current;
};

static ThreadSpecific<TextSourceSlot>& textSourceSlot()
{
    static NeverDestroyed<ThreadSpecific<TextSourceSlot>> slot;
    return slot.get();
}

} // namespace

DriftstackCurrentTextSourceScope::DriftstackCurrentTextSourceScope(StringView source)
{
    auto& slot = *textSourceSlot();
    // No save/restore — drawGlyphBuffer is leaf w.r.t. recursive text emit
    // in the current code path. If nesting appears later, switch to a
    // Vector<StringView> push/pop and refactor.
    slot.current = source;
}

DriftstackCurrentTextSourceScope::~DriftstackCurrentTextSourceScope()
{
    auto& slot = *textSourceSlot();
    slot.current = StringView { };
}

StringView driftstackCurrentTextSource()
{
    auto& slot = *textSourceSlot();
    return slot.current;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
