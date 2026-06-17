/*
 * Per-glyph COLOR-emoji exact-substitution atlas (Driftstack #42 color residual, W2557).
 *
 * Sibling to DriftstackPerGlyphAtlas (DSPGA1, grayscale text). Color emoji are sbix
 * PNG bitmaps; Mac CoreImage downscale AA diverges from iOS for the SAME reason text
 * did — so they are closed the SAME proven way: a per-glyph atlas of the real iPhone's
 * pixels blitted at the per-glyph geometry, instead of native CG rasterization.
 *
 * Stores per-(font_id, pt_size_q4, codepoint, pos_class) -> 64x64 RGBA iPhone-canonical
 * pixels (UNpremultiplied, as canvas getImageData). Atlas hit = bit-identical emoji.
 * Atlas miss = fall through to native CG (current behavior). font_id/pos_class are 0
 * (the color atlas is its own keyspace; integer pen => sub-pixel phase 0).
 *
 * Binary format (DSPGCA1, little-endian) — identical layout to DSPGA1 except pixels
 * is RGBA 16384 not grayscale 4096:
 *   Header (16 bytes):
 *     magic        "DSPGCA1\0"           8 bytes
 *     version      uint32_t              4 bytes
 *     entry_count  uint32_t              4 bytes
 *   Entries (each 16396 bytes, sorted by bytewise memcmp of the 12-byte key):
 *     key:    (font_id u16, pt_size_q4 u16, codepoint u32, pos_class u32)  = 12 bytes
 *     pixels: 64*64*4 uint8_t RGBA row-major                              = 16384 bytes
 *
 * Runtime lookup: O(log N) binary search (mirrors DriftstackPerGlyphAtlas).
 *
 * See captures/v3/build-perglyph-color-atlas.py for the builder.
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace WebCore {

struct DriftstackPerGlyphColorAtlasEntry {
    // 64x64 RGBA iPhone-canonical pixels (row-major, UNpremultiplied).
    // Backed by mmap; lifetime = atlas singleton lifetime.
    const uint8_t* pixels;
    // = 16384
    size_t pixelsSize;
};

class DriftstackPerGlyphColorAtlas {
public:
    static DriftstackPerGlyphColorAtlas& singleton();

    // Lazy auto-load on first access.
    bool loadFromFile(const char* path);

    bool isLoaded() const { return m_loaded; }
    size_t entryCount() const { return m_entryCount; }
    // 1 = DSPGCA1 (lookup key is a bare codepoint); 2 = DSPGCA2 (lookup key is a sequence's
    // seq_hash = FNV-1a-32(utf8) — required for multi-codepoint emoji). The canvas dispatch keys
    // accordingly so a DSPGCA1 atlas keeps its exact current behavior.
    uint32_t version() const { return m_version; }

    // Lookup. Returns nullopt on miss. ptSizeQ4 = static_cast<uint16_t>(round(ptSize * 16)).
    std::optional<DriftstackPerGlyphColorAtlasEntry> lookup(
        uint16_t fontId,
        uint16_t ptSizeQ4,
        uint32_t codepoint,
        uint32_t posClass) const;

    // W2557 (#42 ©®™ residual): true if ANY entry has this codepoint. Used by
    // FontCascade::resolveEmojiPolicy to force emoji-presentation for the baked codepoints
    // (matching iOS's early-Apple-Color-Emoji cascade), so text-default-emoji glyphs the iPhone
    // renders via Apple Color Emoji (©®™ etc.) are classified Color → the canvas dispatch blits
    // the real iPhone pixels. Lazily builds a small codepoint set on first call.
    bool hasCodepoint(uint32_t codepoint) const;

private:
    bool m_loaded { false };
    uint32_t m_version { 1 };   // 1 = DSPGCA1 (codepoint key); 2 = DSPGCA2 (seq_hash key)
    const uint8_t* m_mapBase { nullptr };
    size_t m_mapSize { 0 };
    size_t m_entryCount { 0 };
    const uint8_t* m_entriesBase { nullptr };
    std::vector<uint32_t> m_codepoints; // unique sorted codepoints, for hasCodepoint() (built on load)
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
