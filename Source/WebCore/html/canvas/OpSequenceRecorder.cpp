/*
 * V-581 Path C Phase C-3.A — OpSequenceRecorder canonical serializer
 *
 * See OpSequenceRecorder.h for the canonical format spec and the JS-side
 * counterpart contract.
 */
#include "config.h"
#include "OpSequenceRecorder.h"

#if PLATFORM(DRIFTSTACK)

#include <CommonCrypto/CommonDigest.h>
#include <array>
#include <bit>
#include <cstdlib>
#include <cstring>
#include <wtf/StdLibExtras.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/text/Base64.h>
#include <wtf/text/CString.h>
#include <wtf/text/MakeString.h>
#include <wtf/text/StringView.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(OpSequenceRecorder);

namespace {

// Op id constants — duplicated in the JS table (file
// /captures/v3/v405-canvas-fuzzer.html OP_IDS) and in node test harness
// /captures/v3/test-c1-opseq-sha.js. The contract is byte-identical canonical
// output across all three implementations.
constexpr uint16_t kOpFillRect                  = 0x0001;
constexpr uint16_t kOpStrokeRect                = 0x0002;
constexpr uint16_t kOpClearRect                 = 0x0003;
constexpr uint16_t kOpFillText                  = 0x0004;
constexpr uint16_t kOpStrokeText                = 0x0005;
constexpr uint16_t kOpBeginPath                 = 0x0006;
constexpr uint16_t kOpMoveTo                    = 0x0007;
constexpr uint16_t kOpLineTo                    = 0x0008;
constexpr uint16_t kOpClosePath                 = 0x0009;
constexpr uint16_t kOpFill                      = 0x000A;
constexpr uint16_t kOpStroke                    = 0x000B;
constexpr uint16_t kOpArc                       = 0x000C;
constexpr uint16_t kOpBezierCurveTo             = 0x000E;
constexpr uint16_t kOpRect                      = 0x000F;
constexpr uint16_t kOpFillStyle                 = 0x0020;
constexpr uint16_t kOpStrokeStyle               = 0x0021;
constexpr uint16_t kOpLineWidth                 = 0x0022;
constexpr uint16_t kOpLineCap                   = 0x0023;
constexpr uint16_t kOpLineJoin                  = 0x0024;
constexpr uint16_t kOpMiterLimit                = 0x0025;
constexpr uint16_t kOpFont                      = 0x0028;
constexpr uint16_t kOpTextAlign                 = 0x0029;
constexpr uint16_t kOpTextBaseline              = 0x002A;
constexpr uint16_t kOpGlobalAlpha               = 0x002B;
constexpr uint16_t kOpGlobalCompositeOperation  = 0x002C;
constexpr uint16_t kOpTranslate                 = 0x0032;
constexpr uint16_t kOpScale                     = 0x0033;
constexpr uint16_t kOpRotate                    = 0x0034;

// Argument byte-lengths for fixed-size ops (not used for variable-length
// like strings or fillText). Helps catch bugs at append-time.
constexpr uint16_t kArgsRect4Float              = 4 * 8;  // 4 doubles BE
constexpr uint16_t kArgs2Float                  = 2 * 8;
constexpr uint16_t kArgs1Float                  = 1 * 8;
constexpr uint16_t kArgs0                       = 0;
constexpr uint16_t kArgsArc                     = 5 * 8 + 1;  // 5 doubles + 1 u8 ccw
constexpr uint16_t kArgsBezierCurveTo           = 6 * 8;

inline void appendBigEndianU16(Vector<uint8_t>& buf, uint16_t v)
{
    buf.append(static_cast<uint8_t>((v >> 8) & 0xff));
    buf.append(static_cast<uint8_t>(v & 0xff));
}

inline void appendBigEndianF64(Vector<uint8_t>& buf, double v)
{
    // Write IEEE-754 double in network byte order (big-endian) — both JS
    // (DataView.setFloat64(0, v, false)) and Node (Buffer.writeDoubleBE) do
    // the same; macOS is LE so we byteswap manually. std::bit_cast avoids
    // the -Wunsafe-buffer-usage memcpy form.
    static_assert(sizeof(double) == sizeof(uint64_t), "double must be 8 bytes");
    uint64_t bits = std::bit_cast<uint64_t>(v);
    for (int i = 7; i >= 0; --i)
        buf.append(static_cast<uint8_t>((bits >> (i * 8)) & 0xff));
}

// Core: append [u16 BE byte_len][bytes] from an ALREADY-encoded UTF-8 span (no transcode).
inline void appendU16LenBytesBuf(Vector<uint8_t>& buf, std::span<const char> utf8Span)
{
    auto len = utf8Span.size();
    // Spec: u16 byte_len BE. If a string ever exceeds 65535 bytes we'd need to
    // change the wire format; canvas inputs in practice are well under this.
    if (len > 0xffff) [[unlikely]]
        len = 0xffff;
    appendBigEndianU16(buf, static_cast<uint16_t>(len));
    for (size_t i = 0; i < len; ++i)
        buf.append(static_cast<uint8_t>(utf8Span[i]));
}
inline void appendStringU16LenUTF8Buf(Vector<uint8_t>& buf, const String& s)
{
    auto utf8 = s.utf8();
    appendU16LenBytesBuf(buf, utf8.span());
}

} // anonymous namespace

// P3 (canvas-op-timing-audit): the recorder appends op bytes on EVERY draw op,
// but its output (opSeqSha / canonical bytes) is consumed ONLY at readback, and
// then ONLY when one of these consuming gates is on:
//   DRIFTSTACK_CANVAS_FP10X_OVERRIDE  (V-185 toDataURL/getImageData substitution)
//   DRIFTSTACK_GETIMAGEDATA_ATLAS     (V-510 op-seq-keyed getImageData serve)
//   DRIFTSTACK_PROBE_SIGNATURE_EMIT   (auto-learn ProbeSig harvester)
// When ALL three are off, the recorded buffer is never read, so recording is pure
// discarded work. Skip it: every record method writes exclusively through the
// append primitives below, so gating them makes every recordX a complete no-op
// (no partial/desync'd buffer is possible). In production at least one consuming
// gate is on (DRIFTSTACK_CANVAS_FP10X_OVERRIDE per launch-env) → this is a no-op
// there; the win is render-only / unsubstituted canvases. The recorder output is
// never rendered, so skipping it cannot change a single pixel — byte-neutral.
static bool dsOpRecordingEnabled()
{
    static const bool enabled = []() {
        auto on = [](const char* name) { const char* v = getenv(name); return v && v[0] == '1'; };
        return on("DRIFTSTACK_CANVAS_FP10X_OVERRIDE")
            || on("DRIFTSTACK_GETIMAGEDATA_ATLAS")
            || on("DRIFTSTACK_PROBE_SIGNATURE_EMIT")
            // The canonical-serializer self-test (DRIFTSTACK_TEST_OPSEQ) records
            // into a local recorder and asserts SHA vectors → it needs recording
            // live regardless of the consuming gates.
            || on("DRIFTSTACK_TEST_OPSEQ");
    }();
    return enabled;
}

void OpSequenceRecorder::appendU16BE(uint16_t v)            { if (!dsOpRecordingEnabled()) return; appendBigEndianU16(m_buffer, v); }
void OpSequenceRecorder::appendF64BE(double v)              { if (!dsOpRecordingEnabled()) return; appendBigEndianF64(m_buffer, v); }
void OpSequenceRecorder::appendStringU16LenUTF8(const String& s) { if (!dsOpRecordingEnabled()) return; appendStringU16LenUTF8Buf(m_buffer, s); }
// P4 (canvas-op-timing-audit): the setters already compute v.utf8() for the length — pass it here so the
// string is transcoded ONCE, not twice (the recorder analogue of the toDataURL double-encode). Byte-identical.
void OpSequenceRecorder::appendStringU16LenUTF8(const CString& utf8) { if (!dsOpRecordingEnabled()) return; appendU16LenBytesBuf(m_buffer, utf8.span()); }
void OpSequenceRecorder::appendU8(uint8_t v)                { if (!dsOpRecordingEnabled()) return; m_buffer.append(v); }

void OpSequenceRecorder::appendOpHeader(uint16_t opId, uint16_t argByteLen)
{
    // P-render (canvas-op-timing-audit): amortize the per-op buffer growth — the recorder
    // runs per draw op when a consuming gate is on (prod = FP10X), and on a long-lived
    // canvas every recordX otherwise walks the geometric realloc ladder (16→32→…), each
    // realloc copying the whole accumulated op stream. Pre-size once on the first op of a
    // fresh/cleared buffer so subsequent appends are pure stores. Capacity-only — never
    // touches a single recorded byte (opSeqSha / canonical bytes unchanged) → fingerprint-
    // neutral. (Empirically NOT the dominant render-path 1ms driver — that is the load-
    // bearing forced drawGlyphBuffer rasterization, see CanvasRenderingContext2DBase.cpp
    // drawTextInternal — but a correct, free reduction of real per-draw work regardless.)
    if (m_buffer.isEmpty() && dsOpRecordingEnabled())
        m_buffer.reserveInitialCapacity(2048);
    appendU16BE(opId);
    appendU16BE(argByteLen);
}

// ---- State setters ---------------------------------------------------------

void OpSequenceRecorder::recordSetFillStyle(const String& v)
{
    auto utf8 = v.utf8();
    auto len = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpFillStyle, static_cast<uint16_t>(2 + len));
    appendStringU16LenUTF8(utf8);
}
void OpSequenceRecorder::recordSetStrokeStyle(const String& v)
{
    auto utf8 = v.utf8();
    auto len = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpStrokeStyle, static_cast<uint16_t>(2 + len));
    appendStringU16LenUTF8(utf8);
}
void OpSequenceRecorder::recordSetLineWidth(double v)
{
    appendOpHeader(kOpLineWidth, kArgs1Float);
    appendF64BE(v);
}
void OpSequenceRecorder::recordSetLineCap(const String& v)
{
    auto utf8 = v.utf8();
    auto len = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpLineCap, static_cast<uint16_t>(2 + len));
    appendStringU16LenUTF8(utf8);
}
void OpSequenceRecorder::recordSetLineJoin(const String& v)
{
    auto utf8 = v.utf8();
    auto len = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpLineJoin, static_cast<uint16_t>(2 + len));
    appendStringU16LenUTF8(utf8);
}
void OpSequenceRecorder::recordSetMiterLimit(double v)
{
    appendOpHeader(kOpMiterLimit, kArgs1Float);
    appendF64BE(v);
}
void OpSequenceRecorder::recordSetFont(const String& v)
{
    auto utf8 = v.utf8();
    auto len = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpFont, static_cast<uint16_t>(2 + len));
    appendStringU16LenUTF8(utf8);
}
void OpSequenceRecorder::recordSetTextAlign(const String& v)
{
    auto utf8 = v.utf8();
    auto len = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpTextAlign, static_cast<uint16_t>(2 + len));
    appendStringU16LenUTF8(utf8);
}
void OpSequenceRecorder::recordSetTextBaseline(const String& v)
{
    auto utf8 = v.utf8();
    auto len = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpTextBaseline, static_cast<uint16_t>(2 + len));
    appendStringU16LenUTF8(utf8);
}
void OpSequenceRecorder::recordSetGlobalAlpha(double v)
{
    appendOpHeader(kOpGlobalAlpha, kArgs1Float);
    appendF64BE(v);
}
void OpSequenceRecorder::recordSetGlobalCompositeOperation(const String& v)
{
    auto utf8 = v.utf8();
    auto len = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpGlobalCompositeOperation, static_cast<uint16_t>(2 + len));
    appendStringU16LenUTF8(utf8);
}

// ---- Draw / path ops -------------------------------------------------------

void OpSequenceRecorder::recordFillRect(double x, double y, double w, double h)
{
    appendOpHeader(kOpFillRect, kArgsRect4Float);
    appendF64BE(x); appendF64BE(y); appendF64BE(w); appendF64BE(h);
}
void OpSequenceRecorder::recordStrokeRect(double x, double y, double w, double h)
{
    appendOpHeader(kOpStrokeRect, kArgsRect4Float);
    appendF64BE(x); appendF64BE(y); appendF64BE(w); appendF64BE(h);
}
void OpSequenceRecorder::recordClearRect(double x, double y, double w, double h)
{
    appendOpHeader(kOpClearRect, kArgsRect4Float);
    appendF64BE(x); appendF64BE(y); appendF64BE(w); appendF64BE(h);
}
void OpSequenceRecorder::recordRect(double x, double y, double w, double h)
{
    appendOpHeader(kOpRect, kArgsRect4Float);
    appendF64BE(x); appendF64BE(y); appendF64BE(w); appendF64BE(h);
}
void OpSequenceRecorder::recordFillText(const String& text, double x, double y)
{
    auto utf8 = text.utf8();
    auto strLen = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpFillText, static_cast<uint16_t>(2 + strLen + 2 * 8));
    appendStringU16LenUTF8(utf8);
    appendF64BE(x); appendF64BE(y);
}
void OpSequenceRecorder::recordFillTextWithMaxWidth(const String& text, double x, double y, double maxWidth)
{
    auto utf8 = text.utf8();
    auto strLen = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpFillText, static_cast<uint16_t>(2 + strLen + 3 * 8));
    appendStringU16LenUTF8(utf8);
    appendF64BE(x); appendF64BE(y); appendF64BE(maxWidth);
}
void OpSequenceRecorder::recordStrokeText(const String& text, double x, double y)
{
    auto utf8 = text.utf8();
    auto strLen = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpStrokeText, static_cast<uint16_t>(2 + strLen + 2 * 8));
    appendStringU16LenUTF8(utf8);
    appendF64BE(x); appendF64BE(y);
}
void OpSequenceRecorder::recordStrokeTextWithMaxWidth(const String& text, double x, double y, double maxWidth)
{
    auto utf8 = text.utf8();
    auto strLen = utf8.length() > 0xffff ? 0xffff : utf8.length();
    appendOpHeader(kOpStrokeText, static_cast<uint16_t>(2 + strLen + 3 * 8));
    appendStringU16LenUTF8(utf8);
    appendF64BE(x); appendF64BE(y); appendF64BE(maxWidth);
}
void OpSequenceRecorder::recordBeginPath() { appendOpHeader(kOpBeginPath, kArgs0); }
void OpSequenceRecorder::recordMoveTo(double x, double y)
{
    appendOpHeader(kOpMoveTo, kArgs2Float);
    appendF64BE(x); appendF64BE(y);
}
void OpSequenceRecorder::recordLineTo(double x, double y)
{
    appendOpHeader(kOpLineTo, kArgs2Float);
    appendF64BE(x); appendF64BE(y);
}
void OpSequenceRecorder::recordClosePath() { appendOpHeader(kOpClosePath, kArgs0); }
void OpSequenceRecorder::recordFill()      { appendOpHeader(kOpFill, kArgs0); }
void OpSequenceRecorder::recordStroke()    { appendOpHeader(kOpStroke, kArgs0); }
void OpSequenceRecorder::recordArc(double x, double y, double radius, double startAngle, double endAngle, bool counterClockwise)
{
    appendOpHeader(kOpArc, kArgsArc);
    appendF64BE(x); appendF64BE(y); appendF64BE(radius);
    appendF64BE(startAngle); appendF64BE(endAngle);
    appendU8(counterClockwise ? 1 : 0);
}
void OpSequenceRecorder::recordBezierCurveTo(double cp1x, double cp1y, double cp2x, double cp2y, double x, double y)
{
    appendOpHeader(kOpBezierCurveTo, kArgsBezierCurveTo);
    appendF64BE(cp1x); appendF64BE(cp1y);
    appendF64BE(cp2x); appendF64BE(cp2y);
    appendF64BE(x); appendF64BE(y);
}

// ---- Transforms ------------------------------------------------------------

void OpSequenceRecorder::recordTranslate(double tx, double ty)
{
    appendOpHeader(kOpTranslate, kArgs2Float);
    appendF64BE(tx); appendF64BE(ty);
}
void OpSequenceRecorder::recordScale(double sx, double sy)
{
    appendOpHeader(kOpScale, kArgs2Float);
    appendF64BE(sx); appendF64BE(sy);
}
void OpSequenceRecorder::recordRotate(double angle)
{
    appendOpHeader(kOpRotate, kArgs1Float);
    appendF64BE(angle);
}

// ---- Finalization ----------------------------------------------------------

void OpSequenceRecorder::finalizeSHA256Bytes(uint16_t canvasW, uint16_t canvasH, uint8_t out[32]) const
{
    // Build the canonical full buffer in-place: header + recorded ops.
    Vector<uint8_t> full;
    full.reserveCapacity(5 + m_buffer.size());
    appendBigEndianU16(full, canvasW);
    appendBigEndianU16(full, canvasH);
    full.append(static_cast<uint8_t>(0));  // pixelFormat=0 (RGBA8)
    full.appendVector(m_buffer);

    static_assert(CC_SHA256_DIGEST_LENGTH == 32, "expected 32-byte SHA-256");
    CC_SHA256(full.span().data(), static_cast<CC_LONG>(full.size()), out);
}

String OpSequenceRecorder::finalizeSHA256Hex(uint16_t canvasW, uint16_t canvasH) const
{
    std::array<uint8_t, 32> digest;
    finalizeSHA256Bytes(canvasW, canvasH, digest.data());
    std::array<char, 64> hex;
    static constexpr std::array<char, 16> kLowerHex {{
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    }};
    for (size_t i = 0; i < 32; ++i) {
        hex[i * 2] = kLowerHex[(digest[i] >> 4) & 0xf];
        hex[i * 2 + 1] = kLowerHex[digest[i] & 0xf];
    }
    return String(std::span<const char> { hex });
}

// Wave 29-399 §4 (founder Tier-3 verdict 2026-05-19): canonical bytes
// base64-encoded for §2 ProbeSig emission. BS Automate synthetic harness
// page decodes + replays to capture iPhone canonical output.
//
// Format: same as SHA256 input (header || recorded ops):
//   header = u16BE(canvasW) || u16BE(canvasH) || u8(pixelFormat=0)
//   ops    = m_buffer (canonical-serialized op records)
String OpSequenceRecorder::finalizeCanonicalBytesBase64(uint16_t canvasW, uint16_t canvasH) const
{
    Vector<uint8_t> full;
    full.reserveCapacity(5 + m_buffer.size());
    appendBigEndianU16(full, canvasW);
    appendBigEndianU16(full, canvasH);
    full.append(static_cast<uint8_t>(0));  // pixelFormat=0 (RGBA8)
    full.appendVector(m_buffer);
    // base64Encoded returns Base64Specification (a marker for makeString
    // concatenation, NOT a String). Wrap in makeString to materialize the
    // base64 String. Pattern from DriftstackLayerB.mm:767.
    return makeString(base64Encoded(full.span()));
}

// ---- Self-test (Phase C-3.A) ------------------------------------------------

namespace {

// Test vectors (hardcoded — generated via /tmp/gen-c3-test-vectors.js using the
// JS-side canonical serializer). Updating the canonical format on either side
// requires regenerating these and verifying on both sides simultaneously.
struct ExpectedVector {
    ASCIILiteral name;
    uint16_t canvasW;
    uint16_t canvasH;
    ASCIILiteral expectedSha256;
};

// Test 1: empty 100x100, no ops
constexpr ExpectedVector kVecEmpty = {
    "empty_100x100"_s, 100, 100,
    "a576b72088990fa57390abda8c970f252e32e6b2e9dfe276b01765bf9311358c"_s
};

// Test 2: single fillStyle hex8 + fillRect
//   fillStyle = "#ff0000ff", fillRect(10, 20, 30, 40), 200x200 canvas
constexpr ExpectedVector kVecSingleFillRect = {
    "single_fillRect"_s, 200, 200,
    "e4836b58f881d1a532f2ce8e68351ee4573ac04fac1f78a5954d61a147885c10"_s
};

// Test 3: shapes_compound — multi-op fillStyle / fillRect / fillStyle / arc / fill
//   This matches JS-side test 2 in /captures/v3/test-c1-opseq-sha.js.
constexpr ExpectedVector kVecShapesCompound = {
    "shapes_compound"_s, 300, 200,
    "2599094a6f3743da598444510366cf23c00bd1180a73cebc55cc7a5cca24f026"_s
};

// Test 4: strokes — strokeStyle/lineWidth/lineCap/beginPath/moveTo/lineTo/stroke
constexpr ExpectedVector kVecStrokes = {
    "strokes"_s, 400, 300,
    "1c102150b563eed3"_s  // first 16 hex chars; full would be too long inline
};

// Test 5: text_unicode — fillStyle, font, textBaseline, fillText with CJK + emoji
constexpr ExpectedVector kVecTextUnicode = {
    "text_unicode"_s, 500, 100,
    "4787642245545966"_s
};

// Test 6: transforms — translate, rotate, scale, fillStyle, fillRect
constexpr ExpectedVector kVecTransforms = {
    "transforms"_s, 200, 200,
    "5dd5a0ba2d32bfa2"_s
};

// Test 7: compositing — fillRect, globalAlpha, globalCompositeOperation, fillRect
constexpr ExpectedVector kVecCompositing = {
    "compositing"_s, 200, 200,
    "8b326a569d1857c2"_s
};

// Test 8: complete cubic Bézier path, matching the cross-language float contract.
constexpr ExpectedVector kVecBezier = {
    "bezier_cubic"_s, 200, 60,
    "3161a95f99c82ded4dc3ecf6e8392545bd7f30b770dfb842621430f4a27254e3"_s
};

bool checkResult(ASCIILiteral name, const String& got, ASCIILiteral expected)
{
    // Compare via StringView (bounds-checked). Match if `got` starts with
    // `expected` — test vectors give a 64-char full hash for some cases and
    // a 16-char prefix for others (saves docstring real estate).
    auto gotView = StringView(got);
    auto expectedView = StringView(expected);
    bool match = gotView.length() >= expectedView.length()
        && gotView.left(expectedView.length()) == expectedView;
    if (match)
        WTFLogAlways("[Driftstack-OpSeq-SelfTest] %s: PASS", name.characters());
    else
        WTFLogAlways("[Driftstack-OpSeq-SelfTest] %s: FAIL — expected %s, got %s", name.characters(), expected.characters(), got.utf8().data());
    return match;
}

} // anonymous namespace

void runOpSequenceRecorderSelfTestIfRequested()
{
    // Strict opt-in: env var must be exactly "1". One-char read is safe via
    // unsafeMakeSpan(env, 1) — the null terminator is guaranteed by getenv's
    // C-string contract, so any first-char span is in-bounds. The inverse
    // check (verifying length is exactly 1) requires walking via String, which
    // we avoid for cost reasons; "1<anything>" is treated as match.
    const char* env = std::getenv("DRIFTSTACK_TEST_OPSEQ");
    if (!env)
        return;
    auto envFirst = unsafeMakeSpan(env, 1);
    if (envFirst[0] != '1')
        return;

    WTFLogAlways("[Driftstack-OpSeq-SelfTest] V-581 Phase C-3.A canonical serializer self-test starting...");
    int passes = 0, fails = 0;

    // Test 1
    {
        OpSequenceRecorder r;
        if (checkResult(kVecEmpty.name, r.finalizeSHA256Hex(kVecEmpty.canvasW, kVecEmpty.canvasH), kVecEmpty.expectedSha256))
            ++passes;
        else
            ++fails;
    }

    // Test 2
    {
        OpSequenceRecorder r;
        r.recordSetFillStyle("#ff0000ff"_s);
        r.recordFillRect(10.0, 20.0, 30.0, 40.0);
        if (checkResult(kVecSingleFillRect.name, r.finalizeSHA256Hex(kVecSingleFillRect.canvasW, kVecSingleFillRect.canvasH), kVecSingleFillRect.expectedSha256))
            ++passes;
        else
            ++fails;
    }

    // Test 3
    {
        OpSequenceRecorder r;
        r.recordSetFillStyle("rgb(255,0,0)"_s);
        r.recordFillRect(10.0, 20.0, 30.0, 40.0);
        r.recordSetFillStyle("rgb(0,255,0)"_s);
        r.recordArc(50.0, 50.0, 25.0, 0.0, 6.283185307179586, false);
        r.recordFill();
        if (checkResult(kVecShapesCompound.name, r.finalizeSHA256Hex(kVecShapesCompound.canvasW, kVecShapesCompound.canvasH), kVecShapesCompound.expectedSha256))
            ++passes;
        else
            ++fails;
    }

    // Test 4
    {
        OpSequenceRecorder r;
        r.recordSetStrokeStyle("#0000ffff"_s);
        r.recordSetLineWidth(2.5);
        r.recordSetLineCap("round"_s);
        r.recordBeginPath();
        r.recordMoveTo(10.0, 10.0);
        r.recordLineTo(100.0, 100.0);
        r.recordStroke();
        if (checkResult(kVecStrokes.name, r.finalizeSHA256Hex(kVecStrokes.canvasW, kVecStrokes.canvasH), kVecStrokes.expectedSha256))
            ++passes;
        else
            ++fails;
    }

    // Test 5: unicode (CJK + emoji)
    {
        OpSequenceRecorder r;
        r.recordSetFillStyle("#000000"_s);
        r.recordSetFont("normal 16px \"sans-serif\""_s);
        r.recordSetTextBaseline("alphabetic"_s);
        r.recordFillText(String::fromUTF8("\xe4\xbd\xa0\xe5\xa5\xbd\xe4\xb8\x96\xe7\x95\x8c \xe2\x98\x83 \xf0\x9f\x8e\x89"), 10.0, 50.0);
        if (checkResult(kVecTextUnicode.name, r.finalizeSHA256Hex(kVecTextUnicode.canvasW, kVecTextUnicode.canvasH), kVecTextUnicode.expectedSha256))
            ++passes;
        else
            ++fails;
    }

    // Test 6
    {
        OpSequenceRecorder r;
        r.recordTranslate(50.0, 50.0);
        r.recordRotate(0.7853981633974483);  // pi/4
        r.recordScale(1.5, 0.5);
        r.recordSetFillStyle("#abcdef"_s);
        r.recordFillRect(0.0, 0.0, 50.0, 50.0);
        if (checkResult(kVecTransforms.name, r.finalizeSHA256Hex(kVecTransforms.canvasW, kVecTransforms.canvasH), kVecTransforms.expectedSha256))
            ++passes;
        else
            ++fails;
    }

    // Test 7
    {
        OpSequenceRecorder r;
        r.recordSetFillStyle("#ff0000"_s);
        r.recordFillRect(0.0, 0.0, 100.0, 100.0);
        r.recordSetGlobalAlpha(0.5);
        r.recordSetGlobalCompositeOperation("multiply"_s);
        r.recordSetFillStyle("#0000ff"_s);
        r.recordFillRect(50.0, 50.0, 100.0, 100.0);
        if (checkResult(kVecCompositing.name, r.finalizeSHA256Hex(kVecCompositing.canvasW, kVecCompositing.canvasH), kVecCompositing.expectedSha256))
            ++passes;
        else
            ++fails;
    }

    // Test 8
    {
        OpSequenceRecorder r;
        r.recordSetStrokeStyle("#205"_s);
        r.recordSetLineWidth(3.0);
        r.recordBeginPath();
        r.recordMoveTo(5.0, 55.0);
        r.recordBezierCurveTo(60.0, 5.0, 140.0, 55.0, 195.0, 5.0);
        r.recordStroke();
        if (checkResult(kVecBezier.name, r.finalizeSHA256Hex(kVecBezier.canvasW, kVecBezier.canvasH), kVecBezier.expectedSha256))
            ++passes;
        else
            ++fails;
    }

    WTFLogAlways("[Driftstack-OpSeq-SelfTest] V-581 Phase C-3.A summary: %d PASS / %d FAIL of 8 vectors", passes, fails);
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
