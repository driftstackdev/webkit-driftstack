/*
 * V-770.A.1 — DriftstackTextRunAtlas scaffold (Rule N v2 Layer A).
 *
 * Text-run-keyed atlas for canvas text rendering substitution. Hooked at
 * FontCascade::drawGlyphs entry. On atlas hit, iPhone canonical alpha mask
 * is composited onto the context, bypassing Mac CG rasterization. On miss,
 * pass through to default Mac CG path (Rule O v2 safety baseline).
 *
 * v1 implementation: STUB. lookup() always returns nullopt (empty atlas).
 * Wires the hook in place + emits V-820.A AtlasMiss telemetry on every
 * text run. When V-770.A text-run captures fire, atlas binary gets
 * populated and this lookup() returns hits without further hook code
 * changes.
 *
 * Atlas binary format: DSCFA2 text-run section (defined in
 * captures/v3/build-driftstack-text-run-atlas.py and
 * docs/architecture/wave-28-v770-atlas-builder-v2.md).
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <CoreGraphics/CoreGraphics.h>
#include <cstdint>
#include <optional>
#include <span>
#include <wtf/text/StringView.h>

namespace WebCore {

class Font;
class GraphicsContext;
class FloatPoint;

struct DriftstackTextRunAtlasEntry {
    // Atlas entry payload: alpha-mask PNG bytes + metrics.
    const uint8_t* pngData;
    size_t pngSize;
    float abbLeft;
    float abbRight;
    float abbAscent;
    float abbDescent;
    float width;
};

class DriftstackTextRunAtlas {
public:
    static DriftstackTextRunAtlas& singleton();

    // V-770.A.2: parse + mmap the DSCFA2 atlas binary. Idempotent; safe to
    // call multiple times (returns true on existing-mmap, false on failure).
    // Path resolution: explicit `path` arg, else DRIFTSTACK_TEXT_RUN_ATLAS_PATH
    // env var, else hard-coded fallback. Loaded text-run entries become
    // queryable via lookup(); per-glyph section is ignored (handled by
    // DriftstackTextGlyphAtlas).
    bool loadFromFile(const char* path = nullptr);
    bool isLoaded() const { return m_loaded; }
    size_t entryCount() const { return m_textRunEntryCount; }

    // V-771 lookup entry. Returns hit if (font_id, ptSize, position_class,
    // text_run_hash) is in the atlas binary, else nullopt.
    std::optional<DriftstackTextRunAtlasEntry> lookup(
        uint16_t fontId,
        uint16_t ptSize,
        uint8_t positionClass,
        uint64_t textRunHash);

    // V-820.A integration: each lookup() call increments a counter for
    // telemetry. Telemetry emission is the caller's responsibility via
    // driftstackLogAtlasMiss.
    uint64_t lookupCount() const { return m_lookupCount; }
    uint64_t hitCount() const { return m_hitCount; }
    uint64_t missCount() const { return m_missCount; }

private:
    DriftstackTextRunAtlas() = default;

    bool m_loaded { false };
    void* m_mmapBase { nullptr };
    size_t m_mmapSize { 0 };

    // V-770.A.13: parsed header metadata for diagnostics + future archetype gating.
    uint16_t m_archetypeId { 0 };
    uint8_t m_iosMajor { 0 };
    uint8_t m_iosMinor { 0 };
    uint8_t m_iosPatch { 0 };
public:
    uint16_t archetypeId() const { return m_archetypeId; }
    uint8_t iosMajor() const { return m_iosMajor; }
    uint8_t iosMinor() const { return m_iosMinor; }
    uint8_t iosPatch() const { return m_iosPatch; }
private:

    // V-770.A.3: font table parsed from the atlas binary's font section.
    // postscript_name (or family alias) → font_id. Pointers reference the
    // mmap region directly; no allocation per entry.
    struct FontTableEntry {
        uint16_t fontId;
        const char* nameBytes;
        uint8_t nameLen;
    };
    FontTableEntry* m_fontTable { nullptr };
    uint16_t m_fontTableCount { 0 };

public:
    // Resolve a CSS family / postscript name to the atlas font_id by linear
    // scan of the table (small N ≤ 50). Returns UINT16_MAX if no match.
    uint16_t fontIdForName(const char* name, size_t len) const;
private:

    // Text-run section: parsed at load() into entry table for O(1) lookup.
    // Entries point into the mmap blob region (zero-copy pngData).
    struct TextRunEntry {
        uint32_t blobOffset;
        uint32_t blobSize;
        float abbLeft;
        float abbRight;
        float abbAscent;
        float abbDescent;
        float width;
    };
    // V-770.A.2 simple hash map: combined u64 key. PackedKey is composed as
    // (textRunHash XOR (font_id<<48) XOR (ptSize<<32) XOR positionClass).
    // Collision probability under 100K entries is negligible — re-verified by
    // (font_id, ptSize, positionClass, hash) at hit time via a separate
    // tag check.
    struct PackedKey {
        uint16_t fontId;
        uint16_t ptSize;
        uint8_t positionClass;
        uint64_t textRunHash;
    };
    // Stored as parallel arrays: keys + entries. Keeps memory layout dense
    // and avoids std::unordered_map's per-bucket overhead at 100K+ entries.
    // Lookup uses linear scan WITHIN a coarse bucket indexed by hash low
    // bits — see lookup() body.
    static constexpr size_t kBucketBits = 14;
    static constexpr size_t kBucketCount = (1u << kBucketBits); // 16384
    static constexpr size_t kBucketMask = kBucketCount - 1;
    struct Bucket {
        // Range [first, first+count) into m_textRunKeys/m_textRunEntries.
        uint32_t first { 0 };
        uint32_t count { 0 };
    };
    Bucket m_buckets[kBucketCount] {}; // 128 KB static; small.
    PackedKey* m_textRunKeys { nullptr };       // owned via WTF FastMalloc
    TextRunEntry* m_textRunEntries { nullptr }; // owned via WTF FastMalloc
    size_t m_textRunEntryCount { 0 };
    const uint8_t* m_blobBase { nullptr };
    size_t m_blobSize { 0 };

    uint64_t m_lookupCount { 0 };
    uint64_t m_hitCount { 0 };
    uint64_t m_missCount { 0 };
};

// Helpers (PLATFORM(DRIFTSTACK)-gated).
//
// V-771.B: hash on UTF-8 text bytes + font + ptSize for cross-platform
// parity. Falls back to glyph-buffer hash when textUtf8 is empty (e.g.,
// drawGlyphs call sites outside the FontCascade::drawGlyphBuffer text path).
uint64_t driftstackComputeTextRunHash(
    const Font& font,
    uint16_t ptSize,
    StringView textUtf8,                 // V-771.B primary identity
    std::span<const uint16_t> glyphs,    // CGGlyph == uint16_t (fallback)
    std::span<const CGSize> advances);   // fallback

uint8_t driftstackComputePositionClass(
    CGContextRef cgContext,
    const FloatPoint& anchor);

uint16_t driftstackMapFontToId(const Font& font);

// V-771.B thread-local source-text plumbing.
//
// FontCascade::drawGlyphBuffer receives the source StringView (via F.1.B-6
// plumbing from CanvasRenderingContext2D::fillText). It sets the current
// text source on its thread before invoking GraphicsContext::drawGlyphs,
// which dispatches to the platform Font::drawGlyphs (V-771 hook). The hook
// reads back the source for hash computation. RAII setter clears on exit.
class DriftstackCurrentTextSourceScope {
public:
    explicit DriftstackCurrentTextSourceScope(StringView source);
    ~DriftstackCurrentTextSourceScope();
    DriftstackCurrentTextSourceScope(const DriftstackCurrentTextSourceScope&) = delete;
    DriftstackCurrentTextSourceScope& operator=(const DriftstackCurrentTextSourceScope&) = delete;
};

StringView driftstackCurrentTextSource();

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
