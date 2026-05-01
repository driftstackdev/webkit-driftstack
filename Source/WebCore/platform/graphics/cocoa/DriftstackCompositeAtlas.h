/*
 * DriftstackCompositeAtlas.h — Per V-098 / Phase F.1.B-4 / F.1.B-5
 *
 * mmap'd binary atlas of iPhone-rendered COMPOSITE emoji bitmaps:
 * ZWJ sequences, regional indicators, keycap sequences, skin-tone
 * modifier sequences, VS-16-forced color emoji. Sibling to
 * DriftstackEmojiAtlas (which keys by single codepoint).
 *
 * Atlas format ('DSEC' magic):
 *   header[24]:  magic + version + numStrikes + numEntries + indexOffset + dataOffset
 *   strikes[numStrikes * 4]: strike PPEM table
 *   entries[numEntries * 80]: each entry =
 *     - 64 B: zero-padded UTF-8 sequence (max 64 bytes)
 *     -  2 B: sequenceLen (actual byte count, u16 LE)
 *     -  2 B: strikeIdx (u16 LE)
 *     -  4 B: reserved
 *     -  4 B: offsetInPayload (u32 LE, relative to dataOffset)
 *     -  4 B: pngBytesLen (u32 LE)
 *   data[]: concatenated PNG byte streams
 *
 * Lookup: entries are sorted by (sequence_utf8 lex, strikeIdx). Binary
 * search by sequence then linear scan for matching strikeIdx.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <span>
#include <wtf/NeverDestroyed.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

class DriftstackCompositeAtlas {
public:
    static DriftstackCompositeAtlas& singleton();

    // Returns PNG-encoded bytes for (sequence, strikePPEM), or empty span if not found.
    // sequenceUtf8 is the UTF-8 byte sequence of the emoji codepoint sequence
    // (as captured by JS `String.prototype.codePointAt` then encoded UTF-8).
    std::span<const uint8_t> entryForSequenceAndStrike(std::span<const uint8_t> sequenceUtf8, uint32_t strikePPEM) const;

    // List of strike PPEMs available (e.g., [40, 64, 96, 160]).
    std::span<const uint32_t> strikes() const { return m_strikes.span(); }

    // True iff atlas binary was successfully loaded.
    bool isAvailable() const { return !m_dataPayloadSpan.empty(); }

    // Pick best strike for a given point size: smallest strike >= size,
    // or largest strike if size > all.
    uint32_t pickStrikeForPointSize(float pointSize) const;

private:
    friend NeverDestroyed<DriftstackCompositeAtlas>;
    DriftstackCompositeAtlas();
    ~DriftstackCompositeAtlas();

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
