/*
 * DriftstackEmojiAtlas.h — Per V-088 / Phase F.1.B / D-2026-05-01-21
 *
 * mmap'd binary atlas of iPhone-rendered color emoji bitmaps. Used by
 * FontCascade::drawGlyphs on Driftstack to composite iPhone-equivalent
 * pixels for color-emoji glyphs (instead of letting Mac CoreText
 * render them, which V-082/V-084 confirmed produces structurally
 * different pixels).
 *
 * Atlas format documented at
 * /Users/john/code/driftstack/docs/architecture/option-b-stage-f1-atlas-format.md
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <span>
#include <wtf/NeverDestroyed.h>
#include <wtf/Vector.h>

namespace WebCore {

// Index entry struct exposed for the .mm-side reader. 16 bytes; not
// directly mapped over the mmap due to alignment + safe-buffer rules.
struct DriftstackEmojiAtlas_IndexEntry {
    uint32_t codepoint;
    uint16_t strikeIdx;
    uint16_t reserved;
    uint32_t offsetInPayload;
    uint32_t pngBytesLen;
};

class DriftstackEmojiAtlas {
public:
    static DriftstackEmojiAtlas& singleton();

    // Returns the PNG-encoded bytes for (codepoint, strikePPEM), or empty span if not found.
    // Caller decodes via WebKit's existing PNG infrastructure.
    std::span<const uint8_t> entryForCodepointAndStrike(uint32_t codepoint, uint32_t strikePPEM) const;

    // Returns the list of strike PPEMs available in the atlas (e.g., [40, 64, 96, 160]).
    std::span<const uint32_t> strikes() const { return m_strikes.span(); }

    // Returns true if the atlas was successfully loaded.
    bool isAvailable() const { return !m_dataPayloadSpan.empty(); }

    // Pick the best strike for a given point size: smallest strike >= size,
    // or the largest strike if size > all strikes.
    uint32_t pickStrikeForPointSize(float pointSize) const;

private:
    friend NeverDestroyed<DriftstackEmojiAtlas>;
    DriftstackEmojiAtlas();
    ~DriftstackEmojiAtlas();

    void mapAtlas();

    int m_fd { -1 };
    const uint8_t* m_mmapBase { nullptr };
    size_t m_mmapSize { 0 };

    Vector<uint32_t> m_strikes;
    std::span<const uint8_t> m_indexSpan;
    std::span<const uint8_t> m_dataPayloadSpan;
    size_t m_numEntries { 0 };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
