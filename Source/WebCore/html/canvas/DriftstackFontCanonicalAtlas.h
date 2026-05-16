/*
 * DriftstackFontCanonicalAtlas.h — V-184 measureText random-text extension
 * via mmap'd binary atlas (DSCFM v1).
 *
 * Wave 29-283. Companion to V-184 kCanonicalMetrics (enumerated probe-shape
 * canonical override). This atlas covers RANDOM V-405 fuzzer text patterns
 * captured from real iPhone via BS Automate v405FontFuzzer matrix.
 *
 * Format DSCFM v1 (built by captures/v3/build-v184-font-extension.py):
 *   header[32]: 4B magic 'DSCM' + 2B version=1 + 2B reserved
 *               + 4B numEntries + 4B indexOffset + 4B dataOffset + 12B reserved
 *   index[N × 48B] sorted by key prefix:
 *     16B sha256(family|weight|style|size|text) prefix
 *     + 4B mt_width (f32 LE) + 4B mt_actualBoundingBoxAscent
 *     + 4B mt_actualBoundingBoxDescent + 4B mt_fontBoundingBoxAscent
 *     + 4B mt_fontBoundingBoxDescent + 4B span_w + 4B span_h
 *     + 4B reserved
 *   no data section.
 *
 * Default path: reference/driftstack_font_canonical/v184-font-canonical-v1.bin
 * Override via env var DRIFTSTACK_FONT_CANONICAL_PATH.
 * Env-gated dispatch via DRIFTSTACK_FONT_CANONICAL_OVERRIDE=1.
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>
#include <optional>
#include <span>
#include <wtf/text/WTFString.h>

namespace WebCore {

struct DriftstackFontCanonicalEntry {
    float mtWidth;
    float mtActualBoundingBoxAscent;
    float mtActualBoundingBoxDescent;
    float mtFontBoundingBoxAscent;
    float mtFontBoundingBoxDescent;
    float spanW;
    float spanH;
};

class DriftstackFontCanonicalAtlas {
public:
    static DriftstackFontCanonicalAtlas& singleton();

    bool isLoaded() const { return m_loaded; }
    uint32_t entryCount() const { return m_numEntries; }

    // Look up canonical iPhone measureText result for (family, weight, style, size, text).
    // Returns nullopt on miss.
    std::optional<DriftstackFontCanonicalEntry> lookup(
        const String& family, const String& weight, const String& style,
        unsigned size, const String& text);

    DriftstackFontCanonicalAtlas();
    ~DriftstackFontCanonicalAtlas();

private:
    DriftstackFontCanonicalAtlas(const DriftstackFontCanonicalAtlas&) = delete;
    DriftstackFontCanonicalAtlas& operator=(const DriftstackFontCanonicalAtlas&) = delete;

    void loadOnce();

    bool m_loaded { false };
    void* m_mapped { nullptr };
    size_t m_mappedSize { 0 };
    uint32_t m_numEntries { 0 };
    std::span<const uint8_t> m_indexSpan;
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
