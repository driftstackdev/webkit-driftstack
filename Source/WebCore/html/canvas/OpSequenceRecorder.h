/*
 * V-581 Path C Phase C-3 — OpSequenceRecorder for DSCFA v3 atlas dispatch
 *
 * Records canvas-rendering-context-2D ops in a canonical binary format that
 * is byte-identical to the JS-side recorder in /captures/v3/v405-canvas-fuzzer.html
 * (probe-page schema v3-v405fuzz-1.1-opseq). At toDataURL boundary the recorded
 * buffer is hashed to opSeqSha256, used as DSCFA v3 atlas key.
 *
 * Architectural property: opSeqSha256 is fork-state-independent by construction.
 * Same canvas script produces same key regardless of when/how/with-what-else it
 * runs. V-578 v2 (Mac-output-sha-keyed) loses 100% of multi-cat fork hits per
 * V-578-saturated empirical; v3 atlas keyed by opSeqSha256 will hit 100%
 * across any batch-context combination.
 *
 * Canonical format (file 127 §"Op record format"):
 *   header: [u16 canvasW BE][u16 canvasH BE][u8 pixelFormat=0]
 *   per op: [u16 op_id BE][u16 arg_byte_len BE][arg_bytes...]
 *   floats: IEEE-754 double, big-endian (8 bytes)
 *   strings: u16 byte_len BE + utf-8 bytes
 *   atlas_key = first 16 bytes of SHA256(header || concat(op_records))
 *
 * Op id table (reserves 16-bit ID space; ops 0x0001-0x001F are draw/path,
 * 0x0020-0x002F are state-setters, 0x0030-0x003F are transforms):
 *   0x0001 fillRect / 0x0002 strokeRect / 0x0003 clearRect
 *   0x0004 fillText / 0x0005 strokeText
 *   0x0006 beginPath / 0x0007 moveTo / 0x0008 lineTo / 0x0009 closePath
 *   0x000A fill / 0x000B stroke / 0x000C arc / 0x000F rect
 *   0x0020 fillStyle / 0x0021 strokeStyle / 0x0022 lineWidth
 *   0x0023 lineCap / 0x0024 lineJoin / 0x0025 miterLimit
 *   0x0028 font / 0x0029 textAlign / 0x002A textBaseline
 *   0x002B globalAlpha / 0x002C globalCompositeOperation
 *   0x0032 translate / 0x0033 scale / 0x0034 rotate
 *
 * V-405 fuzzer category coverage: shapes / strokes / text / transforms /
 * compositing all use op-types listed above. New ops added here MUST also be
 * added to the JS-side OP_IDS table in lockstep — the contract is byte-
 * identical canonical output across both implementations.
 *
 * V-581 Phase C-3.A: header + canonical serializer + self-test (this file).
 * V-581 Phase C-3.B: hook every public CanvasRenderingContext2DBase method
 * to call recordX(). V-581 Phase C-3.C: wire opSequenceSHA256() into
 * HTMLCanvasElement::v510AtlasLookup as v3 dispatch path.
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <wtf/Forward.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

class OpSequenceRecorder {
public:
    OpSequenceRecorder() = default;
    ~OpSequenceRecorder() = default;

    OpSequenceRecorder(const OpSequenceRecorder&) = delete;
    OpSequenceRecorder& operator=(const OpSequenceRecorder&) = delete;
    OpSequenceRecorder(OpSequenceRecorder&&) = default;
    OpSequenceRecorder& operator=(OpSequenceRecorder&&) = default;

    // State setters (op 0x0020-0x002F)
    void recordSetFillStyle(const String&);
    void recordSetStrokeStyle(const String&);
    void recordSetLineWidth(double);
    void recordSetLineCap(const String&);
    void recordSetLineJoin(const String&);
    void recordSetMiterLimit(double);
    void recordSetFont(const String&);
    void recordSetTextAlign(const String&);
    void recordSetTextBaseline(const String&);
    void recordSetGlobalAlpha(double);
    void recordSetGlobalCompositeOperation(const String&);

    // Draw / path ops (0x0001-0x001F)
    void recordFillRect(double x, double y, double w, double h);
    void recordStrokeRect(double x, double y, double w, double h);
    void recordClearRect(double x, double y, double w, double h);
    void recordRect(double x, double y, double w, double h);
    void recordFillText(const String& text, double x, double y);
    void recordFillTextWithMaxWidth(const String& text, double x, double y, double maxWidth);
    void recordStrokeText(const String& text, double x, double y);
    void recordStrokeTextWithMaxWidth(const String& text, double x, double y, double maxWidth);
    void recordBeginPath();
    void recordMoveTo(double x, double y);
    void recordLineTo(double x, double y);
    void recordClosePath();
    void recordFill();
    void recordStroke();
    void recordArc(double x, double y, double radius, double startAngle, double endAngle, bool counterClockwise);

    // Transforms (0x0032-0x003F)
    void recordTranslate(double tx, double ty);
    void recordScale(double sx, double sy);
    void recordRotate(double angle);

    // Returns SHA-256 hex (64 chars) of (header || recorded ops). canvasW/H
    // captured from the canvas at finalize-time. Idempotent — safe to call
    // multiple times; does not consume the buffer.
    String finalizeSHA256Hex(uint16_t canvasW, uint16_t canvasH) const;

    // Returns full SHA-256 raw bytes (32 bytes); first 16 = atlas key prefix.
    void finalizeSHA256Bytes(uint16_t canvasW, uint16_t canvasH, uint8_t out[32]) const;

    // Reset for reuse on the same context (e.g. canvas resized → ops invalidated).
    void clear() { m_buffer.clear(); }

    // Diagnostics.
    size_t opByteLength() const { return m_buffer.size(); }
    bool isEmpty() const { return m_buffer.isEmpty(); }

private:
    // Internal serialization helpers — only the op-record bytes; canvas dims
    // are prepended at finalize time.
    void appendOpHeader(uint16_t opId, uint16_t argByteLen);
    void appendU16BE(uint16_t);
    void appendF64BE(double);
    void appendStringU16LenUTF8(const String&);
    void appendU8(uint8_t);

    Vector<uint8_t> m_buffer;
};

// V-581 Phase C-3.A self-test: runs a small set of hardcoded canonical test
// vectors through OpSequenceRecorder and asserts the output matches the JS-
// side reference. Gated on env DRIFTSTACK_TEST_OPSEQ=1; logs PASS/FAIL via
// WTFLogAlways. Called once at WebProcess startup from
// HTMLCanvasElement::initV510AtlasOnce().
void runOpSequenceRecorderSelfTestIfRequested();

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
