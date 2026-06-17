/*
 * DriftstackDOMGeomAtlas — archetype-keyed binary DOM-geometry atlas (W2619).
 *
 * Holds (codepoint, generic-bucket, sizePx) -> (width, height) entries captured
 * from the iOS reference, so the fork's Element.offsetWidth/offsetHeight is
 * bit-identical to a real iPhone for the unbounded exotic-Unicode tail WITHOUT a
 * hand-maintained constexpr table. ADDITIVE: the hardcoded driftstackServeGlyphHashGeom
 * table still owns the verified, glyphHash-locked blocks (General/Supplemental
 * Punctuation, CJK Symbols/Punct, Small Form Variants); this atlas is consulted
 * only for codepoints NOT in that table.
 *
 * ARCHETYPE-AWARE: the atlas file is per-archetype (iPhone model + iOS/Safari
 * version) because DOM-geometry can differ across MAJOR iOS versions (different
 * shipped fonts). The path is resolved from DRIFTSTACK_DOMGEOM_ATLAS_PATH, else
 * built from the active archetype slug (DRIFTSTACK_ARCHETYPE env / config). Minor
 * versions share an atlas (iOS-26.5 sim == real 26.4 byte-identical, W2570).
 *
 * Atlas file format (DDGA, little-endian) — see captures/v3/tools/pack-domgeom-atlas.py:
 *   magic "DDGA" (4) | version u16 (1) | reserved u16 | slug_len u16 |
 *   slug (slug_len, padded to 4) | entryCount u32 |
 *   entries: entryCount * { cp:u32, generic:u8, sizePx:u8, w:u16, h:u16 } (10 bytes,
 *   packed, sorted by (cp, generic, sizePx)).
 *
 * Mirrors the DriftstackAdvanceAtlas (V-689) mmap + binary-search singleton pattern.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstddef>
#include <cstdint>

namespace WebCore {

class DriftstackDOMGeomAtlas {
public:
    static DriftstackDOMGeomAtlas& singleton();

    bool isAvailable() const { return m_entries != nullptr && m_entryCount; }

    // Returns true + sets outW/outH if (cp, generic, sizePx) is present; false on miss.
    bool lookup(uint32_t cp, uint8_t generic, uint8_t sizePx, uint16_t& outW, uint16_t& outH) const;

    uint32_t entryCount() const { return m_entryCount; }

    DriftstackDOMGeomAtlas();

private:
    ~DriftstackDOMGeomAtlas() = default;
    DriftstackDOMGeomAtlas(const DriftstackDOMGeomAtlas&) = delete;
    DriftstackDOMGeomAtlas& operator=(const DriftstackDOMGeomAtlas&) = delete;

    void loadAtlas();

    struct __attribute__((packed)) Entry {
        uint32_t cp;
        uint8_t generic;
        uint8_t sizePx;
        uint16_t w;
        uint16_t h;
    };

    const uint8_t* m_atlasData { nullptr };
    size_t m_atlasSize { 0 };
    const Entry* m_entries { nullptr };
    uint32_t m_entryCount { 0 };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
