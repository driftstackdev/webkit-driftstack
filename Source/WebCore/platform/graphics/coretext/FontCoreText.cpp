/*
 * Copyright (C) 2005-2025 Apple Inc. All rights reserved.
 * Copyright (C) 2006 Alexey Proskuryakov
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "Font.h"

#if PLATFORM(DRIFTSTACK)
#include "../cocoa/DriftstackAdvanceAtlas.h"
#include "../cocoa/DriftstackAsciiAdvanceTable.h"
#include "../cocoa/DriftstackEmoji17Sequences.h"
#include "../cocoa/DriftstackEmojiAtlas.h"
#include "../cocoa/DriftstackNonAsciiAdvanceTable.h"
#include "../cocoa/DriftstackTextGlyphAtlas.h"
#include "../DriftstackKefaAdvances.h"
#include "DriftstackKerningTable.h"
#include "DriftstackPingFangMetrics.h"
#include "DriftstackTrackIMetrics.h"
#include <unordered_map>
#include <unordered_set>
#include <wtf/Lock.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/text/AtomString.h>
#endif

#include "Color.h"
#include "DoublePoint.h"
#include "FloatRect.h"
#include "FontCache.h"
#include "FontCascade.h"
#include "FontCustomPlatformData.h"
#include "FontDescription.h"
#include "LocaleCocoa.h"
#include "Logging.h"
#include "OpenTypeCG.h"
#include "PathCG.h"
#include "SharedBuffer.h"
#include <CoreText/CoreText.h>
#include <float.h>
#include <pal/cf/CoreTextSoftLink.h>
#include <pal/spi/cf/CoreTextSPI.h>
#include <pal/spi/cg/CoreGraphicsSPI.h>
#include <unicode/uchar.h>
#include <wtf/Assertions.h>
#include <wtf/HexNumber.h>
#include <wtf/MathExtras.h>
#include <wtf/RetainPtr.h>
#include <wtf/StdLibExtras.h>
#include <wtf/cf/VectorCF.h>

#if ENABLE(MULTI_REPRESENTATION_HEIC)
#include "MultiRepresentationHEICMetrics.h"
#endif

#include <pal/cf/CoreTextSoftLink.h>

namespace WebCore {

static inline bool caseInsensitiveCompare(CFStringRef a, CFStringRef b)
{
    return a && CFStringCompare(a, b, kCFCompareCaseInsensitive) == kCFCompareEqualTo;
}

static bool fontHasVerticalGlyphs(CTFontRef font)
{
    return fontHasEitherTable(font, kCTFontTableVhea, kCTFontTableVORG);
}

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
bool fontFamilyShouldNotBeUsedForArabic(CFStringRef fontFamilyName)
{
    if (!fontFamilyName)
        return false;

    // Times New Roman and Arial are not performant enough to use. <rdar://problem/21333326>
    // FIXME <rdar://problem/12096835> remove this function once the above bug is fixed.
    return (CFStringCompare(CFSTR("Times New Roman"), fontFamilyName, 0) == kCFCompareEqualTo)
        || (CFStringCompare(CFSTR("Arial"), fontFamilyName, 0) == kCFCompareEqualTo);
}

static const float kLineHeightAdjustment = 0.15f;

static bool shouldUseAdjustment(CTFontRef font)
{
    RetainPtr<CFStringRef> familyName = adoptCF(CTFontCopyFamilyName(font));

    if (!familyName || !CFStringGetLength(familyName.get()))
        return false;

    return caseInsensitiveCompare(familyName.get(), CFSTR("Times"))
        || caseInsensitiveCompare(familyName.get(), CFSTR("Helvetica"))
        || caseInsensitiveCompare(familyName.get(), CFSTR(".Helvetica NeueUI"));
}

#if PLATFORM(DRIFTSTACK)
// Wave 29-291 P-track #46 v2: SF Pro variants get a CONSTANT +1px
// adjustment (NOT the 15% kLineHeightAdjustment which over-shot +12 in
// wave 29-290 revert). iPhone reference (3 BS sessions identical):
// SF Pro 72pt line-height:normal bcr_height = 87, Mac fork = 86, Δ=+1.
// Env-gated DRIFTSTACK_SF_PRO_PLUS_ONE=1 (+ __XPC_*) for staged rollout.
static bool shouldUseSfProConstantOnePixelAdjustment(CTFontRef font)
{
    static bool s_enabled = []() {
        const char* env = getenv("DRIFTSTACK_SF_PRO_PLUS_ONE");
        return env && env[0] == '1';
    }();
    if (!s_enabled)
        return false;
    RetainPtr<CFStringRef> familyName = adoptCF(CTFontCopyFamilyName(font));
    if (!familyName || !CFStringGetLength(familyName.get()))
        return false;
    return caseInsensitiveCompare(familyName.get(), CFSTR(".SF NS"))
        || caseInsensitiveCompare(familyName.get(), CFSTR(".SF NS Display"))
        || caseInsensitiveCompare(familyName.get(), CFSTR(".SF NS Text"))
        || caseInsensitiveCompare(familyName.get(), CFSTR(".AppleSystemUIFont"))
        || caseInsensitiveCompare(familyName.get(), CFSTR("SF Pro"))
        || caseInsensitiveCompare(familyName.get(), CFSTR("SF Pro Display"))
        || caseInsensitiveCompare(familyName.get(), CFSTR("SF Pro Text"))
        // W1434: SF Mono (the system monospace, `ui-monospace` → `.AppleSystemUIFontMonospaced`) is part of
        // the SF system-font family + shares the same iOS-vs-Mac vertical-metric divergence. The h1 UA default
        // (`font-family: ui-monospace`) at 32px was +1 too SHORT (fork 38 vs real 39) precisely because SF Mono
        // wasn't in this list → no +1 (W1431/W1432). Adding it (with the size guard at the call site) matches iOS.
        || caseInsensitiveCompare(familyName.get(), CFSTR(".AppleSystemUIFontMonospaced"))
        || caseInsensitiveCompare(familyName.get(), CFSTR("SF Mono"))
        // W1436: the fork's resolved monospace CTFont reports its family as `.SF NS Mono` (the internal
        // WebKit/CoreText name for SF Mono), NOT `.AppleSystemUIFontMonospaced` (the NSFont API name) — so the
        // W1434 entries above didn't match h1 (stayed +1 too short). Add the `.SF NS Mono` variants. Canvas-safe:
        // the canvas validation uses ZERO monospace at any size (W1433).
        || caseInsensitiveCompare(familyName.get(), CFSTR(".SF NS Mono"))
        || caseInsensitiveCompare(familyName.get(), CFSTR(".SFNSMono"))
        // W2577: `.CJK Symbols Fallback SC` is a SYSTEM-cascade sibling of the SF system font (the fallback
        // for CJK symbols like U+2581 ▁). On a real iPhone it reports the SF vertical ratio (asc/size 0.95215,
        // desc/size 0.24121) — identical bbox + advance to Mac, but Mac CoreText hands back the Mac SF ratio
        // (0.96680/0.21094), which crosses an integer line-box boundary at some sizes → the post-W2575 integer
        // line-box +1/-2 on the glyphHash U+2581 cells (Mac+iOS-26.5-sim verified: SAME font+advance, ratio-only
        // diff). Forcing the iOS SF ratio matches. Canvas-safe: covered fonts are atlas-served (W1443 class).
        || caseInsensitiveCompare(familyName.get(), CFSTR(".CJK Symbols Fallback SC"));
}
#endif

#else

static bool needsAscentAdjustment(CFStringRef familyName)
{
    return familyName && (caseInsensitiveCompare(familyName, CFSTR("Times"))
        || caseInsensitiveCompare(familyName, CFSTR("Helvetica"))
        || caseInsensitiveCompare(familyName, CFSTR("Courier")));
}

#endif

static bool isAhemFont(CFStringRef familyName)
{
    return familyName && caseInsensitiveCompare(familyName, CFSTR("Ahem"));
}

bool fontHasEitherTable(CTFontRef ctFont, unsigned tableTag1, unsigned tableTag2)
{
    return CTFontHasTable(ctFont, tableTag1) || CTFontHasTable(ctFont, tableTag2);
}

void Font::platformInit()
{
    auto constexpr syntheticBoldScaleFactor = 36.0f;
    m_syntheticBoldOffset = m_platformData.syntheticBold() ? (m_platformData.size() / syntheticBoldScaleFactor) : 0.f;

    RetainPtr ctFont = this->ctFont();
    unsigned unitsPerEm = CTFontGetUnitsPerEm(ctFont.get());
    float pointSize = m_platformData.size();
    CGFloat capHeight = pointSize ? CTFontGetCapHeight(ctFont.get()) : 0;
    CGFloat lineGap = pointSize ? CTFontGetLeading(ctFont.get()) : 0;
    CGFloat ascent = pointSize ? CTFontGetAscent(ctFont.get()) : 0;
    CGFloat descent = pointSize ? CTFontGetDescent(ctFont.get()) : 0;

    // The Open Font Format describes the OS/2 USE_TYPO_METRICS flag as follows:
    // "If set, it is strongly recommended to use OS/2.sTypoAscender - OS/2.sTypoDescender+ OS/2.sTypoLineGap as a value for default line spacing for this font."
    // On macOS, we only apply this rule in the important case of fonts with a MATH table.
    if (CTFontHasTable(ctFont.get(), kCTFontTableMATH)) {
        short typoAscent, typoDescent, typoLineGap;
        if (OpenType::tryGetTypoMetrics(ctFont.get(), typoAscent, typoDescent, typoLineGap)) {
            ascent = scaleEmToUnits(typoAscent, unitsPerEm) * pointSize;
            descent = -scaleEmToUnits(typoDescent, unitsPerEm) * pointSize;
            lineGap = scaleEmToUnits(typoLineGap, unitsPerEm) * pointSize;
        }
    }

    auto familyName = adoptCF(CTFontCopyFamilyName(ctFont.get()));

    // Disable antialiasing when rendering with Ahem because many tests require this.
    if (isAhemFont(familyName.get()))
        m_allowsAntialiasing = false;

#if PLATFORM(MAC) && !PLATFORM(DRIFTSTACK)
    // We need to adjust Times, Helvetica, and Courier to closely match the
    // vertical metrics of their Microsoft counterparts that are the de facto
    // web standard. The AppKit adjustment of 20% is too big and is
    // incorrectly added to line spacing, so we use a 15% adjustment instead
    // and add it to the ascent.
    if (origin() == Origin::Local && needsAscentAdjustment(familyName.get()))
        ascent += std::round((ascent + descent) * 0.15f);
#endif

    if (isAhemFont(familyName.get())) {
        auto tolerance = [&] (auto a, auto b) {
            auto toleranceInPixel = 0.01f;
            return toleranceInPixel / std::max(std::abs(a), std::abs(b)) * 100.f;
        };
        auto roundedAscent = std::round(ascent);
        if (WTF::areEssentiallyEqual(ascent, roundedAscent, tolerance(ascent, roundedAscent))) {
            ascent = roundedAscent;
            descent = std::round(descent);
        }
    }

    // Compute line spacing before the line metrics hacks are applied.
#if !PLATFORM(IOS_FAMILY) && !PLATFORM(DRIFTSTACK)
    float lineSpacing = std::lround(ascent) + std::lround(descent) + std::lround(lineGap);
#endif

#if PLATFORM(MAC) && !PLATFORM(DRIFTSTACK)
    // Hack Hiragino line metrics to allow room for marked text underlines.
    // <rdar://problem/5386183>
    if (descent < 3 && lineGap >= 3 && familyName && CFStringHasPrefix(familyName.get(), CFSTR("Hiragino"))) {
        lineGap -= 3 - descent;
        descent = 3;
    }
#endif

    if (platformData().orientation() == FontOrientation::Vertical && !isTextOrientationFallback())
        m_hasVerticalGlyphs = fontHasVerticalGlyphs(ctFont.get());

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
    CGFloat adjustment = shouldUseAdjustment(ctFont.get()) ? ceil((ascent + descent) * kLineHeightAdjustment) : 0;
#if PLATFORM(DRIFTSTACK)
    // P-track #46 v2 (wave 29-291): constant +1 adjustment for SF Pro
    // variants (NOT the 15% kLineHeightAdjustment). Env-gated.
    // W1434 (2026-06-07): the +1 was calibrated at large sizes (72pt: fork 86→87) but OVER-applies at small
    // sizes — empirically (iOS-26.5-sim vs Mac CoreText, W1431) SF system-font ceil-lineSpacing already
    // matches iOS at 11px (both 14) so the +1 there makes the fork 15 = the input/select/textarea/number
    // form-control over-shoot (real iPhone 14). It is still NEEDED at the canvas-validated sizes (≥12px, e.g.
    // 14/32px where iOS's larger descent crosses a ceil boundary). Gate the +1 to pointSize >= 12: this fixes
    // every form-control delta (all 5 SF-Pro controls are 11px; h1 SF Mono is 32px, now hooked above) while
    // leaving the canvas byte-identical — the canvas text shapes use sans-serif at 12px+ and ZERO monospace
    // (W1433 disjoint-region analysis), so nothing the canvas renders changes. Validated cumrig-schema-preserving.
    // W1440/W1452: replace the heuristic +1 with iOS-EXACT SF-family vertical
    // metrics. iOS CoreText SF Pro/Mono are perfectly linear (ascent 0.95215*size,
    // descent 0.24121*size, leading 0; W1431/W1440 14-size iOS-sim sweep) vs Mac
    // CoreText (0.96680/0.21094). The Mac ratios + the constant +1 matched iOS at
    // only 6/14 sizes (over by 1px at 12/15/16/18.72/19/20, +2 at 24); the iOS
    // ratios match at EVERY size -> closes the universal block-element line-height
    // tell (W1439: p/ul/ol/blockquote/hr/fieldset/legend/h3 + the 11px form
    // controls + h1@32 SF Mono) in one override. Canvas-SAFE: the canvas
    // measureText + fingerprint10x are ATLAS-served via DRIFTSTACK_MEASURE_TEXT_
    // OVERRIDE / DRIFTSTACK_CANVAS_FP10X_OVERRIDE (this live FontCoreText ascent
    // is only the fallback for override-uncovered fonts -- CanvasRenderingContext
    // 2DBase.cpp:3456/3479 serve covered fonts from the atlas), so changing it
    // affects only line LAYOUT, not canvas pixels. Validated before/after (W1452).
    if (shouldUseSfProConstantOnePixelAdjustment(ctFont.get())) {
        ascent = 0.95215f * pointSize;
        descent = 0.24121f * pointSize;
        adjustment = 0; // the iOS ratios subsume the +1 at every size
    }
#endif

#if PLATFORM(DRIFTSTACK)
    // W2587: Mac CoreText returns some metrics with tiny floating-point NOISE just above an integer
    // (e.g. Hiragino Sans leading = 8.00002), which ceilf() rounds UP to 9 — where iOS's exact 8.0 ceils
    // to 8. That spurious +1 inflated the line-box / lineSpacing of fallback fonts (the glyphHash
    // U+2581/U+3095 h26-vs-iOS-25 residual). Snap the leading to the nearest integer when it is within
    // kMetricFpEpsilon (pure fp noise, ~2e-5 in practice), else ceil normally (genuine fractional leadings
    // — those ≥0.01 from an integer — are preserved and still round up exactly as iOS does). General: fixes
    // every fallback font whose CoreText leading carries this fp artifact, not just Hiragino.
    {
        constexpr float kMetricFpEpsilon = 0.01f;
        float rounded = std::round(lineGap);
        lineGap = (std::abs(lineGap - rounded) < kMetricFpEpsilon) ? rounded : std::ceil(lineGap);
    }
#else
    lineGap = ceilf(lineGap);
#endif
#if PLATFORM(DRIFTSTACK)
    // Noto Sans Masaram Gondi + Siddham (the host macOS Noto these fall back to) carry the same CoreText
    // fp-noise-above-integer in the ASCENT that W2587 snaps out of the leading: the raw ascent is a hair
    // above iOS's exact integer, so std::ceil below inflates the line-box +1px (blfonts offsetHeight 155/261
    // vs iOS 154/260; descent + Noto Cham match exactly). Snap the ascent to its nearest integer within the
    // metric fp epsilon for these 2 faces only (targeted per the V-493 lesson — not a blanket ascent change).
    if (familyName) {
        String dsNotoFn = String(familyName.get()).convertToASCIILowercase();
        if (dsNotoFn == "noto sans masaram gondi"_s || dsNotoFn == "noto sans siddham"_s) {
            float dsRoundedAscent = std::round(ascent);
            if (std::abs(ascent - dsRoundedAscent) < 0.01f)
                ascent = dsRoundedAscent;
        }
    }
#endif
#if PLATFORM(DRIFTSTACK)
    // 2026-06-27 Kefa Family-A line-box height override (blfonts metricsHash c6bdb116, group "4367,149").
    // CSS family "Kefa" aliases to the macOS face "Kefa III" (FontCacheCoreText, Safari<26 only). Mac
    // "Kefa III" carries a TALLER line-box than real iOS "Kefa": at 128px Mac CoreText returns
    // ascent=125.439453 (.97999*em) descent=28.160156 (.22000*em) leading=0 -> ceil(126)+ceil(29)+0 = 155,
    // but real iOS Kefa's line-box is 149 (captured blfonts offsetHeight, kefaPerChar.fullKefaBcr.h=149,
    // group key "4367,149"). This +6 is a genuine ascent/descent divergence between the two PHYSICAL faces
    // (NOT the W2587 fp-noise-above-integer artifact: 125.439/28.160 are far from any integer) -> the
    // W2587/Noto ascent-snap above CANNOT fix it. Override the resolved "Kefa III" FontMetrics to land the
    // iOS line-box (ceil(ascent)+ceil(descent)+leading == 149). The captured ground truth gives only the
    // line-box SUM (149), not iOS Kefa's ascent/descent SPLIT, so we scale Mac Kefa III's own asc/desc
    // proportionally (preserves the Mac ratio = minimal baseline-position disturbance) to the smallest
    // pair whose ceil-sum is 149: ascent .94206*em, descent .21148*em. Family-A ONLY (driftstackKefaAdvances
    // Active) — on >=26 Kefa is absent so "Kefa III" never resolves; verified no 26.4/26.5 effect. The
    // metricsHash group keys on (offsetWidth,offsetHeight); the width half is the genuine per-glyph advances
    // (DriftstackKefaAdvances.h Latin + DriftstackGcpsFallback.h GCPS). Scale-by-pointSize: ratios * size.
    // ⚠️ EMPIRICAL: the asc/desc SPLIT is ratio-preserved-from-Mac, not a captured iOS split (Rule 15: a BS
    // capture of iOS Kefa's hhea ascent/descent would pin the exact split; the line-box SUM=149 closes the
    // metricsHash group regardless, since blfonts groups on offsetHeight). A3 must re-render to confirm 149.
    if (pointSize > 0.f && driftstackKefaAdvancesActive() && familyName
        && String(familyName.get()) == "Kefa III"_s) {
        // .94206*128 = 120.584 -> ceil 121 ; .21148*128 = 27.069 -> ceil 28 ; sum 149.
        ascent = 0.94206f * pointSize;
        descent = 0.21148f * pointSize;
        lineGap = 0.f; // Mac Kefa III leading is already 0; pin it so the ceil-sum is exactly 149.
    }
#endif
#if PLATFORM(DRIFTSTACK)
    // W2980d/f (#120 glyph-1600 cluster A fantasy +1 + cluster C per-face +2 snap). RE-ROOT-CAUSED.
    // The browserleaks /fonts Unicode-Glyphs FP renders each cp's span at font-size:10000% of the
    // font:initial 16px box = 1600px, line-height:normal (the testbox `font:initial` resets line-height
    // to normal — verified empirically: the 1600px default strut is 1910 = 1.19*size, BELOW the body's
    // 1.5*1600=2400 floor, so the floor is NOT in play; the font line-box IS the measured offsetHeight).
    //
    // ⛔ CORRECTION of W2980b (251b13bf73): the CSS `fantasy` generic on this build resolves to ZAPFINO,
    // NOT Papyrus. The earlier Papyrus snap was a no-op because (a) Papyrus is the wrong font and (b)
    // Mac Papyrus's lineSpacing@1600 is 2469 (asc 1503.906 desc 964.844), nowhere near the fantasy column's
    // 5404/5405. CoreText probe (Apple-Silicon dev box, captures/v3 strut_scan.m) proves Zapfino@1600 gives
    // asc=3000.000000, desc=2404.003906, lead=0 → ceil(3000)+ceil(2404.0039)+0 = 3000+2405 = 5405 (the fork
    // value, every fantasy cp), where a real iPhone 17 / Safari 26.4 returns 5404. The +1 is the descent's
    // CoreText fp-noise-just-above-integer: Zapfino's true descent ratio is exactly 1.5025*em, and
    // 1.5025*1600 = 2404.0 + 0.0039 — ceilf() rounds that to 2405 where iOS's exact 2404.0 ceils flat. The
    // W2587 leading snap covers the leading only (Zapfino lead=0) and the Noto/Papyrus ascent snaps cover
    // other faces; Zapfino's descent is NOT snapped, so the lineSpacing line below ceils it +1. Snap Zapfino
    // ascent AND descent to their nearest integer when within kMetricFpEpsilon (the W2587/Noto pattern), so
    // the ceilf lands the iOS line-box 5404. This is the W2587 fp-noise class (the |Δ| at 1600 is 0.0039),
    // NOT the Kefa-III genuine-divergence class — verified: snapping reproduces iOS's exact 5404.
    //
    // 16px-SAFE BY CONSTRUCTION (DOUBLE GUARD): (1) gated to pointSize >= 100 → fires ONLY at the 1600px
    // probe band, NEVER at the 16/13px glyphHash sizes or the 128px font-detection size; (2) the snap is a
    // no-op except where |Δ| < 0.01 — and CoreText probe shows Zapfino's desc fraction is 0.040 @16px /
    // 0.320 @128px (both >0.01, so even WITHOUT the pointSize gate the 16/128 values are untouched: 55 / 433
    // unchanged). The 16px fantasy cell is a flat per-generic constant (28, line-height floored) and the
    // glyphHash c587ed44 surface is the 16/13px Element.cpp serve (size-gated, untouched at 1600px) — so this
    // is structurally invisible to c587ed44 / metricsHash / uniqueMetrics / the 178 identical cells. Pure
    // large-size line-LAYOUT correction; canvas/measureText are atlas-served (DRIFTSTACK_MEASURE_TEXT_OVERRIDE)
    // so pixels are untouched too. A3: re-render the faithful 1600px probe → assert all 43 fantasy cells ==
    // …5404 (NOT 5405) AND 16px fantasy still 28 (c587ed44 held).
    //
    // CURATED ALLOWLIST (W2980d cluster A + W2980f cluster C): the W2587 LEADING fp-noise snap, applied to the
    // ASCENT and DESCENT of a VERIFIED set of faces at large size only. The same CoreText fp-noise-just-above-
    // integer that W2587 snaps out of the leading also appears in the ascent/descent of these faces, and at
    // 1600px it ceils +1/+2 where iOS's exact integer ceils flat. CoreText-probed (captures/v3 zapfino.m/
    // kohinoor.m/bleed.m/a830.m), each is a genuine W2587-class fp-noise (|Δ| < 0.01 ONLY at 1600px), NOT a
    // Kefa-III genuine divergence:
    //   - Zapfino       (fantasy)       desc 2404.0039 → 2404  → fantasy 5405→5404  (cluster A, 43 cells)
    //   - Kohinoor Dev. (U+097F)        asc 1680.0034 / desc 560.0011 → 2402→2400   (cluster C +2, 6 cells)
    //   - Hiragino Sans (U+2581/3095)   asc 1408.0029 / desc 192.0004 → 2402→2400   (cluster C +2 bleed, 8 cells)
    //   - Mukta Mahee   (U+A830)        asc 1808.0078              → 2661→2660       (cluster C +1, 5 cells)
    //
    // ⛔ NOT GENERALIZED to all faces (the V-493 lesson + a regression caught this session): APPLE COLOR EMOJI
    // also has the fp-noise (asc 1600.0001 / desc 500.00003 @1600) BUT iOS produces the SAME ceiled-up value
    // (the emoji-presentation cells U+2B06/U+20E3 sans/serif/mono are CORRECT at 2102 in the fork == ref) —
    // i.e. iOS's Apple-Color-Emoji line-box is NOT exact-integer there, so snapping it would REGRESS 6+
    // currently-identical cells 2102→2100. The "iOS metrics are exact integers" premise holds per-face, not
    // universally → snap ONLY the faces verified to close the grid TOWARD iOS, never a blanket asc/desc snap.
    //
    // 16px-SAFE BY DOUBLE GUARD: (1) pointSize >= 100 → fires ONLY at the 1600px probe band, NEVER at the
    // 16/13px glyphHash sizes or 128px detection size; (2) the snap is a no-op unless |Δ| < 0.01, and every
    // allowlisted face's fp-noise residue is >0.01 at 16px AND 128px (Zapfino 0.040/0.320, Kohinoor 0.20/0.40,
    // Hiragino 0.080/0.360, Mukta 0.080/0.359) — so 16/128 are untouched even without the size gate. The
    // glyphHash c587ed44 surface is the 16/13px Element.cpp serve (size-gated). Canvas/measureText are
    // atlas-served. A3: re-render the faithful 1600px probe → assert fantasy …5404 + U+097F all-gen 2400 +
    // U+2581/3095 sans/serif/mono/cursive 2400 + U+A830 all-gen 2660; 16px fantasy still 28 + c587ed44 held +
    // the emoji cells U+2B06/U+20E3 sans/serif/mono UNCHANGED at 2102.
    if (pointSize >= 100.f && familyName) {
        String dsSnapFn = String(familyName.get());
        if (equalLettersIgnoringASCIICase(dsSnapFn, "zapfino"_s)
            || equalLettersIgnoringASCIICase(dsSnapFn, "papyrus"_s)
            || equalLettersIgnoringASCIICase(dsSnapFn, "kohinoor devanagari"_s)
            || equalLettersIgnoringASCIICase(dsSnapFn, "itf devanagari"_s)
            || equalLettersIgnoringASCIICase(dsSnapFn, "hiragino sans"_s)
            || equalLettersIgnoringASCIICase(dsSnapFn, "mukta mahee"_s)) {
            constexpr float kMetricFpEpsilon = 0.01f;
            float dsRoundedAscent = std::round(ascent);
            if (std::abs(ascent - dsRoundedAscent) < kMetricFpEpsilon)
                ascent = dsRoundedAscent;
            float dsRoundedDescent = std::round(descent);
            if (std::abs(descent - dsRoundedDescent) < kMetricFpEpsilon)
                descent = dsRoundedDescent;
        }
    }
#endif
#if PLATFORM(DRIFTSTACK)
    // Emoji 17 UI-context fallbacks use face1 of the bundled TTC because the
    // host hidden UI face predates those glyphs. Directly materializing face1
    // loses the hidden face's shorter vertical geometry, so overlay the same
    // host-system probe used for its contextual advance. A missing/unexpected
    // host identity fails open to the bundled face's natural metrics.
    if (driftstackIsBundledAppleColorEmojiUIFont(ctFont.get())) {
        auto geometry = driftstackSystemEmojiUIGeometry(pointSize);
        if (geometry) {
            ascent = geometry.ascent;
            descent = geometry.descent;
            lineGap = geometry.leading;
        }
    }
#endif
    float lineSpacing = std::ceil(ascent) + adjustment + std::ceil(descent) + lineGap;
    ascent = ceilf(ascent + adjustment);
    descent = ceilf(descent);

#if PLATFORM(DRIFTSTACK)
    // W2572 instrumentation (gated default-off): pin the -apple-system large-size offsetHeight cap.
    // Hypothesis: the SF-Pro iOS-ratio override (shouldUseSfProConstantOnePixelAdjustment) does NOT fire
    // at large sizes because the resolved Display optical-variant's family name isn't in the match list,
    // so the fork falls back to raw Mac CoreText metrics (ascent+descent ~116 at 128px) instead of the
    // iOS ratios (153). Logs the resolved family name + metrics. Reverted after pinning.
    if (getenv("DRIFTSTACK_LOG_FONT_METRIC")) {
        char buf[160] = {0};
        if (familyName)
            CFStringGetCString(familyName.get(), buf, sizeof(buf), kCFStringEncodingUTF8);
        WTFLogAlways("[W2572-FM] family='%s' size=%.1f ascent=%.2f descent=%.2f lineGap=%.2f lineSpacing=%.2f sfProOverride=%d",
            buf, pointSize, ascent, descent, lineGap, lineSpacing,
            shouldUseSfProConstantOnePixelAdjustment(ctFont.get()) ? 1 : 0);
    }
#endif

#if PLATFORM(DRIFTSTACK)
    // V-602 PingFang metric overlay + Track I generalization (wave 29-233):
    // Mac-resolved fallback fonts that diverge from iOS equivalents get
    // metric override here. Table-driven pattern — each entry maps a Mac
    // family name to the iOS target metric source. Add new entries as
    // empirical divergences emerge.
    //
    // Original V-602 hardcoded Hiragino→PingFang block is now entry [0]
    // in kDriftstackFontMetricOverrides. Future Track I entries follow.
    //
    // Env-gated DRIFTSTACK_V602_SUBSTITUTE=1 (legacy name preserved for
    // back-compat; semantically gates ALL Track I overrides). Off by
    // default — production sessions explicitly enable.
    static bool s_metricOverridesEnabled = []() {
        const char* env = getenv("DRIFTSTACK_V602_SUBSTITUTE");
        return env && env[0] == '1';
    }();
    if (s_metricOverridesEnabled && familyName) {
        // Wave 29-240 Slice 240.1: Track I override entry extended to support
        // BOTH per-weight metric resolution (PingFang variants — V-602) and
        // static metric values (Track I non-CJK fonts — wave 29-239 capture).
        //
        // resolveMetric: function ptr; if non-null, weight-dependent lookup
        // staticMetric: pointer to TrackIFontMetric; if non-null, static
        // exactly one is non-null per entry.
        struct DriftstackFontMetricOverrideEntry {
            CFStringRef macFamilyName;
            const WebCore::Driftstack::PingFangMetricEntry& (*resolveMetric)(uint16_t cssWeight);
            const WebCore::Driftstack::TrackIFontMetric* staticMetric;
        };
        static const DriftstackFontMetricOverrideEntry kOverrideTable[] = {
            // V-602 (per-weight): Mac Hiragino → iOS PingFang
            { CFSTR(".Hiragino Kaku Gothic Interface"), &WebCore::Driftstack::pingFangMetricForWeight, nullptr },
            { CFSTR("Hiragino Kaku Gothic"),            &WebCore::Driftstack::pingFangMetricForWeight, nullptr },
            { CFSTR("HiraginoSans"),                    &WebCore::Driftstack::pingFangMetricForWeight, nullptr },
            // Track I (wave 29-239 capture) REVERTED wave 29-242 r4 after cumrig 1259/337
            // regression vs 1264 baseline. Hypothesis: Mac CT returns iPhone-equivalent metrics
            // natively for these fonts; applying iOS-side overrides DIVERGED from natural match.
            // Header DriftstackTrackIMetrics.h retained for future per-archetype-divergence
            // re-deployment when empirical data justifies it.
            // { CFSTR("Devanagari Sangam MN"),  nullptr, &WebCore::Driftstack::kTrackIFontMetrics[0] },
            // { CFSTR("Geeza Pro"),             nullptr, &WebCore::Driftstack::kTrackIFontMetrics[1] },
            // { CFSTR("Hebrew"),                nullptr, &WebCore::Driftstack::kTrackIFontMetrics[2] },
            // { CFSTR("Khmer Sangam MN"),       nullptr, &WebCore::Driftstack::kTrackIFontMetrics[3] },
            // { CFSTR("Kohinoor Devanagari"),   nullptr, &WebCore::Driftstack::kTrackIFontMetrics[4] },
            // { CFSTR("Thonburi"),              nullptr, &WebCore::Driftstack::kTrackIFontMetrics[5] },
        };
        const DriftstackFontMetricOverrideEntry* matchedEntry = nullptr;
        for (const auto& entry : kOverrideTable) {
            if (CFStringCompare(familyName.get(), entry.macFamilyName, 0) == kCFCompareEqualTo) {
                matchedEntry = &entry;
                break;
            }
        }
        if (matchedEntry) {
            uint16_t cssWeight = 400; // default Regular
            uint16_t targetUnitsPerEm;
            int16_t targetTypoAscent;
            int16_t targetTypoDescent;
            int16_t targetTypoLineGap;
            const char* targetLabel = "?";

            if (matchedEntry->resolveMetric) {
                // V-602 per-weight resolution
                RetainPtr<CTFontDescriptorRef> v602Desc = adoptCF(CTFontCopyFontDescriptor(ctFont.get()));
                if (v602Desc) {
                    RetainPtr<CFDictionaryRef> traits = adoptCF(static_cast<CFDictionaryRef>(
                        CTFontDescriptorCopyAttribute(v602Desc.get(), kCTFontTraitsAttribute)));
                    if (traits) {
                        CFNumberRef weightNum = static_cast<CFNumberRef>(
                            CFDictionaryGetValue(traits.get(), kCTFontWeightTrait));
                        if (weightNum) {
                            float ctWeight = 0.f;
                            CFNumberGetValue(weightNum, kCFNumberFloatType, &ctWeight);
                            cssWeight = static_cast<uint16_t>(std::clamp(
                                400.0f + ctWeight * 400.0f, 100.0f, 900.0f));
                        }
                    }
                }
                const auto& targetMetric = matchedEntry->resolveMetric(cssWeight);
                targetUnitsPerEm = targetMetric.unitsPerEm;
                targetTypoAscent = targetMetric.typoAscent;
                targetTypoDescent = targetMetric.typoDescent;
                targetTypoLineGap = targetMetric.typoLineGap;
                targetLabel = targetMetric.label;
            } else if (matchedEntry->staticMetric) {
                // Track I static metric
                targetUnitsPerEm = matchedEntry->staticMetric->unitsPerEm;
                targetTypoAscent = matchedEntry->staticMetric->typoAscent;
                targetTypoDescent = matchedEntry->staticMetric->typoDescent;
                targetTypoLineGap = matchedEntry->staticMetric->typoLineGap;
                targetLabel = matchedEntry->staticMetric->label;
            } else {
                // Malformed entry; skip
                targetUnitsPerEm = unitsPerEm;
                targetTypoAscent = 0;
                targetTypoDescent = 0;
                targetTypoLineGap = 0;
            }
            unitsPerEm = targetUnitsPerEm;
            ascent = scaleEmToUnits(targetTypoAscent, unitsPerEm) * pointSize;
            descent = -scaleEmToUnits(targetTypoDescent, unitsPerEm) * pointSize;
            lineGap = scaleEmToUnits(targetTypoLineGap, unitsPerEm) * pointSize;
            WTFLogAlways("[Driftstack-Track-I] metric overlay applied (cssWeight=%u, target=%s, ascent=%.1f, descent=%.1f, lineGap=%.1f at %.1fpt)",
                static_cast<unsigned>(cssWeight), targetLabel,
                static_cast<double>(ascent), static_cast<double>(descent),
                static_cast<double>(lineGap), static_cast<double>(pointSize));
        }
    }

    // V-081 Stage D-2 Track 1: iPhone reports a different per-size
    // fontBoundingBox{Ascent,Descent} for the public Apple Color Emoji face
    // than Mac's CoreText returns from the same iOS font binary. Captured
    // per-size empirically (Stage D-3 Set A, sizes [8..96]). The hidden UI
    // face is intentionally excluded: its natural shorter metrics are what
    // keep SF-system fallback inside the primary font's line box.
    if (familyName && caseInsensitiveCompare(familyName.get(), CFSTR("Apple Color Emoji"))) {
        struct DriftstackEmojiFontMetricsEntry { float size; float ascent; float descent; };
        static constexpr std::array<DriftstackEmojiFontMetricsEntry, 89> driftstackEmojiFontMetricsTable = {{
            {  8.f, 10.f,  4.f }, {  9.f, 12.f,  4.f }, { 10.f, 13.f,  4.f }, { 11.f, 14.f,  5.f },
            { 12.f, 15.f,  5.f }, { 13.f, 17.f,  6.f }, { 14.f, 18.f,  6.f }, { 15.f, 19.f,  6.f },
            { 16.f, 20.f,  7.f }, { 17.f, 21.f,  7.f }, { 18.f, 21.f,  7.f }, { 19.f, 22.f,  7.f },
            { 20.f, 22.f,  7.f }, { 21.f, 23.f,  8.f }, { 22.f, 23.f,  8.f }, { 23.f, 24.f,  8.f },
            { 24.f, 25.f,  8.f }, { 25.f, 26.f,  8.f }, { 26.f, 27.f,  9.f }, { 27.f, 28.f,  9.f },
            { 28.f, 29.f,  9.f }, { 29.f, 30.f, 10.f }, { 30.f, 31.f, 10.f }, { 31.f, 32.f, 10.f },
            { 32.f, 33.f, 11.f }, { 33.f, 34.f, 11.f }, { 34.f, 35.f, 11.f }, { 35.f, 36.f, 11.f },
            { 36.f, 37.f, 12.f }, { 37.f, 38.f, 12.f }, { 38.f, 39.f, 12.f }, { 39.f, 40.f, 13.f },
            { 40.f, 41.f, 13.f }, { 41.f, 42.f, 13.f }, { 42.f, 43.f, 14.f }, { 43.f, 44.f, 14.f },
            { 44.f, 45.f, 14.f }, { 45.f, 46.f, 15.f }, { 46.f, 47.f, 15.f }, { 47.f, 48.f, 15.f },
            { 48.f, 49.f, 16.f }, { 49.f, 50.f, 16.f }, { 50.f, 51.f, 16.f }, { 51.f, 52.f, 16.f },
            { 52.f, 53.f, 17.f }, { 53.f, 54.f, 17.f }, { 54.f, 55.f, 17.f }, { 55.f, 56.f, 18.f },
            { 56.f, 57.f, 18.f }, { 57.f, 58.f, 18.f }, { 58.f, 59.f, 19.f }, { 59.f, 60.f, 19.f },
            { 60.f, 61.f, 19.f }, { 61.f, 62.f, 20.f }, { 62.f, 63.f, 20.f }, { 63.f, 64.f, 20.f },
            { 64.f, 65.f, 21.f }, { 65.f, 66.f, 21.f }, { 66.f, 67.f, 21.f }, { 67.f, 68.f, 21.f },
            { 68.f, 69.f, 22.f }, { 69.f, 70.f, 22.f }, { 70.f, 71.f, 22.f }, { 71.f, 72.f, 23.f },
            { 72.f, 73.f, 23.f }, { 73.f, 74.f, 23.f }, { 74.f, 75.f, 24.f }, { 75.f, 76.f, 24.f },
            { 76.f, 77.f, 24.f }, { 77.f, 78.f, 25.f }, { 78.f, 79.f, 25.f }, { 79.f, 80.f, 25.f },
            { 80.f, 81.f, 26.f }, { 81.f, 82.f, 26.f }, { 82.f, 83.f, 26.f }, { 83.f, 84.f, 26.f },
            { 84.f, 85.f, 27.f }, { 85.f, 86.f, 27.f }, { 86.f, 87.f, 27.f }, { 87.f, 88.f, 28.f },
            { 88.f, 89.f, 28.f }, { 89.f, 90.f, 28.f }, { 90.f, 91.f, 29.f }, { 91.f, 92.f, 29.f },
            { 92.f, 93.f, 29.f }, { 93.f, 94.f, 30.f }, { 94.f, 95.f, 30.f }, { 95.f, 96.f, 30.f },
            { 96.f, 97.f, 31.f }
        }};
        const float emojiSize = m_platformData.size();
        // W2596: only use the captured table within its optical range [8..96]. For emojiSize > 96
        // LINEAR-EXTRAPOLATE the iPhone table (NOT the natural Stage-B font metrics — the Stage-B
        // AppleColorEmoji-160px.ttc ascent is exactly 128.0 → ceil 128 → line box 168 @128px, but
        // the real iPhone is 170: ceil 129 + 41). Extrapolating from the table's size-64 and size-96
        // entries (slope +1/size ascent, +0.3125/size descent) yields 129/41 @128px → lineSpacing
        // 170 == iOS uniqueMetrics emoji height. The old code capped at the 96px row {97,31} → ~128
        // (gross); same cap class as the W2577 -apple-system fix.
        if (emojiSize <= driftstackEmojiFontMetricsTable.back().size) {
            if (emojiSize <= driftstackEmojiFontMetricsTable.front().size) {
                ascent = driftstackEmojiFontMetricsTable.front().ascent;
                descent = driftstackEmojiFontMetricsTable.front().descent;
            } else if (emojiSize >= driftstackEmojiFontMetricsTable.back().size) {
                ascent = driftstackEmojiFontMetricsTable.back().ascent;
                descent = driftstackEmojiFontMetricsTable.back().descent;
            } else {
                DriftstackEmojiFontMetricsEntry a = driftstackEmojiFontMetricsTable.front();
                for (const auto& b : driftstackEmojiFontMetricsTable) {
                    if (emojiSize >= a.size && emojiSize <= b.size && a.size != b.size) {
                        float t = (emojiSize - a.size) / (b.size - a.size);
                        ascent  = a.ascent  + t * (b.ascent  - a.ascent);
                        descent = a.descent + t * (b.descent - a.descent);
                        break;
                    }
                    a = b;
                }
            }
        } else {
            // emojiSize > 96: reproduce iOS CoreText's EXACT AppleColorEmoji FontMetrics floats (not just the
            // ceil-sum). AppleColorEmoji.ttc (uPM=800, hhea ascent=800 descent=-250, leading=0) scales in
            // CoreText at a constant point-size epsilon — VERIFIED via CTFontGetAscent/Descent @97..600px:
            //   ascent = size + 1e-4 ,  descent = 0.3125*size + 3.125e-5 ,  leading = 0
            // (byte-identical on macOS + iOS: same font binary). The OLD table-slope extrapolation ceil-summed
            // right (201+63=264) but carried the WRONG raw float sub-structure → the CreepJS getClientRects
            // line box landed 2^-15 (1 float32 ULP) below iOS (fork 264.2637634277344 vs iPhone-17
            // 264.2637939453125, creepjsdomrect-iPhone_17-1782878388485). Serving iOS's exact floats threads
            // the right residual through the subpixel line-box assembly. ceil-sum + lineSpacing UNCHANGED at
            // every size (129/170/198/264/395/527/789 @97/128/150/200/300/400/600 — W2596 128px→170 + glyphHash
            // preserved); the 16..96px table path (glyphHash 16/13px) is untouched.
            ascent  = static_cast<float>(static_cast<double>(emojiSize) + 0.0001);
            descent = static_cast<float>(static_cast<double>(emojiSize) * (250.0 / 800.0) + 0.00003125);
        }
        // W2588: the table above replaces ascent/descent with the iOS Apple Color Emoji
        // values, but lineSpacing was computed earlier (≈line 304) from Mac CoreText's RAW
        // emoji metrics, which are SMALLER — so lineSpacing (21 at 16px) ends up LESS than
        // ceil(ascent)+ceil(descent) (27). In the CSS normal-line-height half-leading calc
        // (InlineLineBoxBuilder enclosingAscentDescentWithFallbackFonts) that negative gap
        // SHRINKS the emoji's line-box contribution back down to 21, producing a -5px
        // div.offsetHeight tell on the browserleaks glyphHash surface for every emoji
        // fall-through glyph (U+2B06, U+20E3, …). iOS emoji leading is 0, so make lineSpacing
        // consistent with the overridden ascent/descent (half-leading becomes 0, line box = 27).
        lineSpacing = std::ceil(ascent) + std::ceil(descent) + lineGap;
    }

    // V-083 Track 3: per-size fontBoundingBox{Ascent,Descent} overrides
    // for non-emoji fonts where Mac CoreText returns metrics that diverge
    // from iPhone's. Captured per-size via Track 3 BS Automate run
    // (track3-non-emoji-fonts.html), 6 fonts × 89 sizes = 534 reference
    // probes. Of the 6 fonts, 3 (Gujarati Sangam MN / Oriya Sangam MN /
    // Plantagenet Cherokee) share identical metrics → one shared table.
    {
        struct DriftstackTrack3Entry { float size; float ascent; float descent; };
        static constexpr std::array<DriftstackTrack3Entry, 89> track3TimesTable = {{
            {   8.f,   8.f,   2.f }, {   9.f,   9.f,   2.f }, {  10.f,   9.f,   3.f }, {  11.f,  10.f,   3.f },
            {  12.f,  11.f,   3.f }, {  13.f,  12.f,   3.f }, {  14.f,  13.f,   4.f }, {  15.f,  14.f,   4.f },
            {  16.f,  15.f,   4.f }, {  17.f,  16.f,   4.f }, {  18.f,  17.f,   4.f }, {  19.f,  17.f,   5.f },
            {  20.f,  18.f,   5.f }, {  21.f,  19.f,   5.f }, {  22.f,  20.f,   5.f }, {  23.f,  21.f,   5.f },
            {  24.f,  22.f,   6.f }, {  25.f,  23.f,   6.f }, {  26.f,  24.f,   6.f }, {  27.f,  25.f,   6.f },
            {  28.f,  25.f,   7.f }, {  29.f,  26.f,   7.f }, {  30.f,  27.f,   7.f }, {  31.f,  28.f,   7.f },
            {  32.f,  29.f,   7.f }, {  33.f,  30.f,   8.f }, {  34.f,  31.f,   8.f }, {  35.f,  32.f,   8.f },
            {  36.f,  33.f,   8.f }, {  37.f,  33.f,   9.f }, {  38.f,  34.f,   9.f }, {  39.f,  35.f,   9.f },
            {  40.f,  36.f,   9.f }, {  41.f,  37.f,   9.f }, {  42.f,  38.f,  10.f }, {  43.f,  39.f,  10.f },
            {  44.f,  40.f,  10.f }, {  45.f,  41.f,  10.f }, {  46.f,  41.f,  10.f }, {  47.f,  42.f,  11.f },
            {  48.f,  43.f,  11.f }, {  49.f,  44.f,  11.f }, {  50.f,  45.f,  11.f }, {  51.f,  46.f,  12.f },
            {  52.f,  47.f,  12.f }, {  53.f,  48.f,  12.f }, {  54.f,  49.f,  12.f }, {  55.f,  50.f,  12.f },
            {  56.f,  50.f,  13.f }, {  57.f,  51.f,  13.f }, {  58.f,  52.f,  13.f }, {  59.f,  53.f,  13.f },
            {  60.f,  54.f,  13.f }, {  61.f,  55.f,  14.f }, {  62.f,  56.f,  14.f }, {  63.f,  57.f,  14.f },
            {  64.f,  58.f,  14.f }, {  65.f,  58.f,  15.f }, {  66.f,  59.f,  15.f }, {  67.f,  60.f,  15.f },
            {  68.f,  61.f,  15.f }, {  69.f,  62.f,  15.f }, {  70.f,  63.f,  16.f }, {  71.f,  64.f,  16.f },
            {  72.f,  65.f,  16.f }, {  73.f,  66.f,  16.f }, {  74.f,  66.f,  17.f }, {  75.f,  67.f,  17.f },
            {  76.f,  68.f,  17.f }, {  77.f,  69.f,  17.f }, {  78.f,  70.f,  17.f }, {  79.f,  71.f,  18.f },
            {  80.f,  72.f,  18.f }, {  81.f,  73.f,  18.f }, {  82.f,  74.f,  18.f }, {  83.f,  74.f,  18.f },
            {  84.f,  75.f,  19.f }, {  85.f,  76.f,  19.f }, {  86.f,  77.f,  19.f }, {  87.f,  78.f,  19.f },
            {  88.f,  79.f,  20.f }, {  89.f,  80.f,  20.f }, {  90.f,  81.f,  20.f }, {  91.f,  82.f,  20.f },
            {  92.f,  82.f,  20.f }, {  93.f,  83.f,  21.f }, {  94.f,  84.f,  21.f }, {  95.f,  85.f,  21.f },
            {  96.f,  86.f,  21.f }
        }};
        static constexpr std::array<DriftstackTrack3Entry, 89> track3AppleSystemTable = {{
            {   8.f,   8.f,   2.f }, {   9.f,   9.f,   3.f }, {  10.f,  10.f,   3.f }, {  11.f,  11.f,   3.f },
            {  12.f,  12.f,   3.f }, {  13.f,  13.f,   4.f }, {  14.f,  14.f,   4.f }, {  15.f,  15.f,   4.f },
            {  16.f,  16.f,   4.f }, {  17.f,  17.f,   5.f }, {  18.f,  18.f,   5.f }, {  19.f,  19.f,   5.f },
            {  20.f,  20.f,   5.f }, {  21.f,  20.f,   6.f }, {  22.f,  21.f,   6.f }, {  23.f,  22.f,   6.f },
            {  24.f,  23.f,   6.f }, {  25.f,  24.f,   7.f }, {  26.f,  25.f,   7.f }, {  27.f,  26.f,   7.f },
            {  28.f,  27.f,   7.f }, {  29.f,  28.f,   7.f }, {  30.f,  29.f,   8.f }, {  31.f,  30.f,   8.f },
            {  32.f,  31.f,   8.f }, {  33.f,  32.f,   8.f }, {  34.f,  33.f,   9.f }, {  35.f,  34.f,   9.f },
            {  36.f,  35.f,   9.f }, {  37.f,  36.f,   9.f }, {  38.f,  37.f,  10.f }, {  39.f,  38.f,  10.f },
            {  40.f,  39.f,  10.f }, {  41.f,  40.f,  10.f }, {  42.f,  40.f,  11.f }, {  43.f,  41.f,  11.f },
            {  44.f,  42.f,  11.f }, {  45.f,  43.f,  11.f }, {  46.f,  44.f,  12.f }, {  47.f,  45.f,  12.f },
            {  48.f,  46.f,  12.f }, {  49.f,  47.f,  12.f }, {  50.f,  48.f,  13.f }, {  51.f,  49.f,  13.f },
            {  52.f,  50.f,  13.f }, {  53.f,  51.f,  13.f }, {  54.f,  52.f,  14.f }, {  55.f,  53.f,  14.f },
            {  56.f,  54.f,  14.f }, {  57.f,  55.f,  14.f }, {  58.f,  56.f,  14.f }, {  59.f,  57.f,  15.f },
            {  60.f,  58.f,  15.f }, {  61.f,  59.f,  15.f }, {  62.f,  60.f,  15.f }, {  63.f,  60.f,  16.f },
            {  64.f,  61.f,  16.f }, {  65.f,  62.f,  16.f }, {  66.f,  63.f,  16.f }, {  67.f,  64.f,  17.f },
            {  68.f,  65.f,  17.f }, {  69.f,  66.f,  17.f }, {  70.f,  67.f,  17.f }, {  71.f,  68.f,  18.f },
            {  72.f,  69.f,  18.f }, {  73.f,  70.f,  18.f }, {  74.f,  71.f,  18.f }, {  75.f,  72.f,  19.f },
            {  76.f,  73.f,  19.f }, {  77.f,  74.f,  19.f }, {  78.f,  75.f,  19.f }, {  79.f,  76.f,  20.f },
            {  80.f,  77.f,  20.f }, {  81.f,  78.f,  20.f }, {  82.f,  79.f,  20.f }, {  83.f,  80.f,  21.f },
            {  84.f,  80.f,  21.f }, {  85.f,  81.f,  21.f }, {  86.f,  82.f,  21.f }, {  87.f,  83.f,  21.f },
            {  88.f,  84.f,  22.f }, {  89.f,  85.f,  22.f }, {  90.f,  86.f,  22.f }, {  91.f,  87.f,  22.f },
            {  92.f,  88.f,  23.f }, {  93.f,  89.f,  23.f }, {  94.f,  90.f,  23.f }, {  95.f,  91.f,  23.f },
            {  96.f,  92.f,  24.f }
        }};
        static constexpr std::array<DriftstackTrack3Entry, 89> track3IndicSharedTable = {{
            {   8.f,   9.f,   2.f }, {   9.f,   9.f,   3.f }, {  10.f,  10.f,   3.f }, {  11.f,  11.f,   3.f },
            {  12.f,  12.f,   3.f }, {  13.f,  13.f,   3.f }, {  14.f,  14.f,   4.f }, {  15.f,  15.f,   4.f },
            {  16.f,  16.f,   4.f }, {  17.f,  17.f,   4.f }, {  18.f,  17.f,   5.f }, {  19.f,  18.f,   5.f },
            {  20.f,  20.f,   5.f }, {  21.f,  21.f,   5.f }, {  22.f,  21.f,   6.f }, {  23.f,  22.f,   6.f },
            {  24.f,  23.f,   6.f }, {  25.f,  24.f,   6.f }, {  26.f,  25.f,   6.f }, {  27.f,  26.f,   7.f },
            {  28.f,  27.f,   7.f }, {  29.f,  28.f,   7.f }, {  30.f,  29.f,   7.f }, {  31.f,  29.f,   8.f },
            {  32.f,  30.f,   8.f }, {  33.f,  31.f,   8.f }, {  34.f,  33.f,   8.f }, {  35.f,  33.f,   9.f },
            {  36.f,  34.f,   9.f }, {  37.f,  35.f,   9.f }, {  38.f,  36.f,   9.f }, {  39.f,  37.f,   9.f },
            {  40.f,  38.f,  10.f }, {  41.f,  39.f,  10.f }, {  42.f,  40.f,  10.f }, {  43.f,  41.f,  10.f },
            {  44.f,  41.f,  11.f }, {  45.f,  42.f,  11.f }, {  46.f,  43.f,  11.f }, {  47.f,  45.f,  11.f },
            {  48.f,  45.f,  12.f }, {  49.f,  46.f,  12.f }, {  50.f,  47.f,  12.f }, {  51.f,  48.f,  12.f },
            {  52.f,  49.f,  12.f }, {  53.f,  49.f,  13.f }, {  54.f,  51.f,  13.f }, {  55.f,  52.f,  13.f },
            {  56.f,  53.f,  13.f }, {  57.f,  53.f,  14.f }, {  58.f,  54.f,  14.f }, {  59.f,  55.f,  14.f },
            {  60.f,  57.f,  14.f }, {  61.f,  57.f,  15.f }, {  62.f,  58.f,  15.f }, {  63.f,  59.f,  15.f },
            {  64.f,  60.f,  15.f }, {  65.f,  61.f,  15.f }, {  66.f,  61.f,  16.f }, {  67.f,  63.f,  16.f },
            {  68.f,  64.f,  16.f }, {  69.f,  65.f,  16.f }, {  70.f,  65.f,  17.f }, {  71.f,  66.f,  17.f },
            {  72.f,  67.f,  17.f }, {  73.f,  68.f,  17.f }, {  74.f,  69.f,  18.f }, {  75.f,  70.f,  18.f },
            {  76.f,  71.f,  18.f }, {  77.f,  72.f,  18.f }, {  78.f,  73.f,  18.f }, {  79.f,  73.f,  19.f },
            {  80.f,  75.f,  19.f }, {  81.f,  76.f,  19.f }, {  82.f,  77.f,  19.f }, {  83.f,  77.f,  20.f },
            {  84.f,  78.f,  20.f }, {  85.f,  79.f,  20.f }, {  86.f,  80.f,  20.f }, {  87.f,  81.f,  21.f },
            {  88.f,  82.f,  21.f }, {  89.f,  83.f,  21.f }, {  90.f,  84.f,  21.f }, {  91.f,  85.f,  21.f },
            {  92.f,  85.f,  22.f }, {  93.f,  86.f,  22.f }, {  94.f,  88.f,  22.f }, {  95.f,  89.f,  22.f },
            {  96.f,  89.f,  23.f }
        }};
        static constexpr std::array<DriftstackTrack3Entry, 89> track3TeluguSangamTable = {{
            {   8.f,   9.f,   3.f }, {   9.f,  10.f,   4.f }, {  10.f,  11.f,   4.f }, {  11.f,  12.f,   4.f },
            {  12.f,  13.f,   5.f }, {  13.f,  14.f,   5.f }, {  14.f,  15.f,   5.f }, {  15.f,  16.f,   6.f },
            {  16.f,  17.f,   6.f }, {  17.f,  18.f,   6.f }, {  18.f,  19.f,   7.f }, {  19.f,  20.f,   7.f },
            {  20.f,  21.f,   7.f }, {  21.f,  23.f,   8.f }, {  22.f,  24.f,   8.f }, {  23.f,  25.f,   9.f },
            {  24.f,  26.f,   9.f }, {  25.f,  27.f,   9.f }, {  26.f,  28.f,  10.f }, {  27.f,  29.f,  10.f },
            {  28.f,  30.f,  10.f }, {  29.f,  31.f,  11.f }, {  30.f,  32.f,  11.f }, {  31.f,  33.f,  11.f },
            {  32.f,  34.f,  12.f }, {  33.f,  35.f,  12.f }, {  34.f,  36.f,  12.f }, {  35.f,  37.f,  13.f },
            {  36.f,  38.f,  13.f }, {  37.f,  39.f,  13.f }, {  38.f,  40.f,  14.f }, {  39.f,  41.f,  14.f },
            {  40.f,  42.f,  14.f }, {  41.f,  44.f,  15.f }, {  42.f,  45.f,  15.f }, {  43.f,  46.f,  16.f },
            {  44.f,  47.f,  16.f }, {  45.f,  48.f,  16.f }, {  46.f,  49.f,  17.f }, {  47.f,  50.f,  17.f },
            {  48.f,  51.f,  17.f }, {  49.f,  52.f,  18.f }, {  50.f,  53.f,  18.f }, {  51.f,  54.f,  18.f },
            {  52.f,  55.f,  19.f }, {  53.f,  56.f,  19.f }, {  54.f,  57.f,  19.f }, {  55.f,  58.f,  20.f },
            {  56.f,  59.f,  20.f }, {  57.f,  60.f,  20.f }, {  58.f,  61.f,  21.f }, {  59.f,  62.f,  21.f },
            {  60.f,  63.f,  21.f }, {  61.f,  65.f,  22.f }, {  62.f,  66.f,  22.f }, {  63.f,  67.f,  23.f },
            {  64.f,  68.f,  23.f }, {  65.f,  69.f,  23.f }, {  66.f,  70.f,  24.f }, {  67.f,  71.f,  24.f },
            {  68.f,  72.f,  24.f }, {  69.f,  73.f,  25.f }, {  70.f,  74.f,  25.f }, {  71.f,  75.f,  25.f },
            {  72.f,  76.f,  26.f }, {  73.f,  77.f,  26.f }, {  74.f,  78.f,  26.f }, {  75.f,  79.f,  27.f },
            {  76.f,  80.f,  27.f }, {  77.f,  81.f,  27.f }, {  78.f,  82.f,  28.f }, {  79.f,  83.f,  28.f },
            {  80.f,  84.f,  28.f }, {  81.f,  86.f,  29.f }, {  82.f,  87.f,  29.f }, {  83.f,  88.f,  30.f },
            {  84.f,  89.f,  30.f }, {  85.f,  90.f,  30.f }, {  86.f,  91.f,  31.f }, {  87.f,  92.f,  31.f },
            {  88.f,  93.f,  31.f }, {  89.f,  94.f,  32.f }, {  90.f,  95.f,  32.f }, {  91.f,  96.f,  32.f },
            {  92.f,  97.f,  33.f }, {  93.f,  98.f,  33.f }, {  94.f,  99.f,  33.f }, {  95.f, 100.f,  34.f },
            {  96.f, 101.f,  34.f }
        }};

        // Match family by lowercased name. The 6 fonts collapse into 4
        // tables (Gujarati/Oriya/Plantagenet share the indic table).
        const std::span<const DriftstackTrack3Entry> matchedTable = [&]() -> std::span<const DriftstackTrack3Entry> {
            if (!familyName)
                return { };
            String fn = String(familyName.get()).convertToASCIILowercase();
            if (fn == "times"_s)
                return std::span<const DriftstackTrack3Entry>(track3TimesTable);
            if (fn == ".applesystemuifont"_s || fn == "applesystemuifont"_s || fn == "-apple-system"_s)
                return std::span<const DriftstackTrack3Entry>(track3AppleSystemTable);
            if (fn == "gujarati sangam mn"_s || fn == "oriya sangam mn"_s || fn == "plantagenet cherokee"_s)
                return std::span<const DriftstackTrack3Entry>(track3IndicSharedTable);
            if (fn == "telugu sangam mn"_s)
                return std::span<const DriftstackTrack3Entry>(track3TeluguSangamTable);
            return { };
        }();

        if (!matchedTable.empty()) {
            const float track3Size = m_platformData.size();
            if (track3Size <= matchedTable.front().size) {
                ascent = matchedTable.front().ascent;
                descent = matchedTable.front().descent;
            } else if (track3Size >= matchedTable.back().size) {
                // W2577: the Track-3 per-size table only covers [8..96]. For the SF system font
                // (.AppleSystemUIFont), the SF-Pro vertical metrics are genuinely LINEAR above 96px
                // (0.95215/0.24121 — fontTools hhea/OS2-verified; CoreText scales linearly past the
                // opsz axis cap of 96 — the cap affects glyph SHAPE, not metric SCALE). The flat clamp
                // to the 96px row (ascent 92/descent 24) capped -apple-system & system-ui offsetHeight
                // at ~116-117 for ALL sizes >=96 (sim-verified: fork 117 vs iOS 121/135/153/192 at
                // 100/112/128/160px). For SF fonts, SKIP the clamp so the correct linear values already
                // set by shouldUseSfProConstantOnePixelAdjustment (lines ~274-278, ceil'd ~283-284)
                // survive. Non-SF tables (Times/Indic/Telugu) keep the clamp — they are NOT SF-linear
                // and have no verified >96 iOS metric.
                if (!shouldUseSfProConstantOnePixelAdjustment(ctFont.get())) {
                    ascent = matchedTable.back().ascent;
                    descent = matchedTable.back().descent;
                }
            } else {
                DriftstackTrack3Entry a = matchedTable.front();
                for (const auto& b : matchedTable) {
                    if (track3Size >= a.size && track3Size <= b.size && a.size != b.size) {
                        float t = (track3Size - a.size) / (b.size - a.size);
                        ascent  = a.ascent  + t * (b.ascent  - a.ascent);
                        descent = a.descent + t * (b.descent - a.descent);
                        break;
                    }
                    a = b;
                }
            }
        }
    }
#endif

    m_shouldNotBeUsedForArabic = fontFamilyShouldNotBeUsedForArabic(familyName.get());
#endif

    CGFloat xHeight = 0;
    if (m_platformData.size()) {
        if (platformData().orientation() == FontOrientation::Horizontal) {
            // Measure the actual character "x", since it's possible for it to extend below the baseline, and we need the
            // reported x-height to only include the portion of the glyph that is above the baseline.
            Glyph xGlyph = glyphForCharacter('x');
            if (xGlyph)
                xHeight = -CGRectGetMinY(platformBoundsForGlyph(xGlyph));
            else
                xHeight = CTFontGetXHeight(ctFont.get());
        } else
            xHeight = verticalRightOrientationFont().fontMetrics().xHeight().value_or(0);
    }

    if (CTFontGetSymbolicTraits(ctFont.get()) & kCTFontTraitColorGlyphs) {
        if (RetainPtr cfBitVector = adoptCF(CTFontCopyColorGlyphCoverage(ctFont.get())))
            m_emojiType = SomeEmojiGlyphs { BitVector(cfBitVector.get()) };
        else
            m_emojiType = NoEmojiGlyphs { };
    } else
        m_emojiType = NoEmojiGlyphs { };

    // V-493 ROLLED BACK 2026-05-08 — empirically refuted (V-log V-2026-05-08-493).
    // V-484 hypothesis (FontMetrics override family closes 32 complexScripts
    // diffs) was wrong-layer. Pre-V-493 Mac CTFont infrastructure
    // (CTFontGetAscent + kLineHeightAdjustment hack at line ~205) ALREADY
    // produces iPhone-matching fontBoundingBoxAscent/Descent for the iOS
    // Stage B fonts (Hiragino 14pt = 13/2; PingFang HK 14pt = 15/5; both
    // matched iPhone canonical). V-493 forced raw hhea values, breaking 14
    // previously-correct surfaces. V-220 already documented this exact
    // failure mode. The 32 complexScripts residuals (actualBoundingBoxAscent/
    // Descent + width per text run) are downstream of FontMetrics — likely
    // in Font::platformBoundsForGlyph for complex-script glyphs or in the
    // text shaping / glyph buffer construction layer. V-484 needs redesign
    // at the correct layer; not landing FontMetrics override.

    m_fontMetrics.setUnitsPerEm(unitsPerEm);
    m_fontMetrics.setAscent(ascent);
    m_fontMetrics.setDescent(descent);
    m_fontMetrics.setCapHeight(capHeight);
    m_fontMetrics.setLineGap(lineGap);
    m_fontMetrics.setXHeight(xHeight);
    m_fontMetrics.setLineSpacing(lineSpacing);
    m_fontMetrics.setUnderlinePosition(-CTFontGetUnderlinePosition(ctFont.get()));
    m_fontMetrics.setUnderlineThickness(CTFontGetUnderlineThickness(ctFont.get()));
}

void Font::platformCharWidthInit()
{
    m_avgCharWidth = 0;
    m_maxCharWidth = 0;

    RetainPtr ctFont = this->ctFont();
    auto os2Table = adoptCF(CTFontCopyTable(ctFont.get(), kCTFontTableOS2, kCTFontTableOptionNoOptions));
    if (os2Table && CFDataGetLength(os2Table.get()) >= 4) {
        auto os2 = span(os2Table.get());
        SInt16 os2AvgCharWidth = os2[2] * 256 + os2[3];
        m_avgCharWidth = scaleEmToUnits(os2AvgCharWidth, m_fontMetrics.unitsPerEm()) * m_platformData.size();
    }

    auto headTable = adoptCF(CTFontCopyTable(ctFont.get(), kCTFontTableHead, kCTFontTableOptionNoOptions));
    if (headTable && CFDataGetLength(headTable.get()) >= 42) {
        auto head = span(headTable.get());
        unsigned uxMin = head[36] * 256 + head[37];
        unsigned uxMax = head[40] * 256 + head[41];
        SInt16 xMin = static_cast<SInt16>(uxMin);
        SInt16 xMax = static_cast<SInt16>(uxMax);
        float diff = static_cast<float>(xMax - xMin);
        m_maxCharWidth = scaleEmToUnits(diff, m_fontMetrics.unitsPerEm()) * m_platformData.size();
    }

    // Fallback to a cross-platform estimate, which will populate these values if they are non-positive.
    initCharWidths();
}

bool Font::variantCapsSupportedForSynthesis(FontVariantCaps fontVariantCaps) const
{
    switch (fontVariantCaps) {
    case FontVariantCaps::Small:
        return supportsSmallCaps();
    case FontVariantCaps::Petite:
        return supportsPetiteCaps();
    case FontVariantCaps::AllSmall:
        return supportsAllSmallCaps();
    case FontVariantCaps::AllPetite:
        return supportsAllPetiteCaps();
    default:
        // Synthesis only supports the variant-caps values listed above.
        return true;
    }
}

static RetainPtr<CFDictionaryRef> smallCapsOpenTypeDictionary(CFStringRef key, int rawValue)
{
    RetainPtr<CFNumberRef> value = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &rawValue));
    CFTypeRef keys[] = { kCTFontOpenTypeFeatureTag, kCTFontOpenTypeFeatureValue };
    CFTypeRef values[] = { key, value.get() };
    return adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
}

static RetainPtr<CFDictionaryRef> smallCapsTrueTypeDictionary(int rawKey, int rawValue)
{
    RetainPtr<CFNumberRef> key = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &rawKey));
    RetainPtr<CFNumberRef> value = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &rawValue));
    CFTypeRef keys[] = { kCTFontFeatureTypeIdentifierKey, kCTFontFeatureSelectorIdentifierKey };
    CFTypeRef values[] = { key.get(), value.get() };
    return adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
}

static void unionBitVectors(BitVector& result, CFBitVectorRef source)
{
    CFIndex length = CFBitVectorGetCount(source);
    result.ensureSize(length);
    CFIndex min = 0;
    while (min < length) {
        CFIndex nextIndex = CFBitVectorGetFirstIndexOfBit(source, CFRangeMake(min, length - min), 1);
        if (nextIndex == kCFNotFound)
            break;
        result.set(nextIndex, true);
        min = nextIndex + 1;
    }
}

static void injectOpenTypeCoverage(CFStringRef feature, CTFontRef font, BitVector& result)
{
    RetainPtr<CFBitVectorRef> source = adoptCF(CTFontCopyGlyphCoverageForFeature(font, smallCapsOpenTypeDictionary(feature, 1).get()));
    unionBitVectors(result, source.get());
}

static void injectTrueTypeCoverage(int type, int selector, CTFontRef font, BitVector& result)
{
    RetainPtr<CFBitVectorRef> source = adoptCF(CTFontCopyGlyphCoverageForFeature(font, smallCapsTrueTypeDictionary(type, selector).get()));
    unionBitVectors(result, source.get());
}

bool Font::supportsOpenTypeAlternateHalfWidths() const
{
    if (m_supportsOpenTypeAlternateHalfWidths == SupportsFeature::Unknown)
        m_supportsOpenTypeAlternateHalfWidths = supportsOpenTypeFeature(protect(ctFont()).get(), CFSTR("halt")) ? SupportsFeature::Yes : SupportsFeature::No;
    return m_supportsOpenTypeAlternateHalfWidths == SupportsFeature::Yes;
}

bool Font::supportsSmallCaps() const
{
    if (m_supportsSmallCaps == SupportsFeature::Unknown) {
        BitVector glyphsSupportedBySmallCaps;
        RetainPtr ctFont = this->ctFont();
        injectOpenTypeCoverage(CFSTR("smcp"), ctFont.get(), glyphsSupportedBySmallCaps);
        injectTrueTypeCoverage(kLowerCaseType, kLowerCaseSmallCapsSelector, ctFont.get(), glyphsSupportedBySmallCaps);
        m_supportsSmallCaps = glyphsSupportedBySmallCaps.isEmpty() ? SupportsFeature::No : SupportsFeature::Yes;
    }
    return m_supportsSmallCaps == SupportsFeature::Yes;
}

bool Font::supportsAllSmallCaps() const
{
    if (m_supportsAllSmallCaps == SupportsFeature::Unknown) {
        BitVector glyphsSupportedByAllSmallCaps;
        RetainPtr ctFont = this->ctFont();
        injectOpenTypeCoverage(CFSTR("smcp"), ctFont.get(), glyphsSupportedByAllSmallCaps);
        injectOpenTypeCoverage(CFSTR("c2sc"), ctFont.get(), glyphsSupportedByAllSmallCaps);
        injectTrueTypeCoverage(kLowerCaseType, kLowerCaseSmallCapsSelector, ctFont.get(), glyphsSupportedByAllSmallCaps);
        injectTrueTypeCoverage(kUpperCaseType, kUpperCaseSmallCapsSelector, ctFont.get(), glyphsSupportedByAllSmallCaps);
        m_supportsAllSmallCaps = glyphsSupportedByAllSmallCaps.isEmpty() ? SupportsFeature::No : SupportsFeature::Yes;
    }
    return m_supportsAllSmallCaps == SupportsFeature::Yes;
}

bool Font::supportsPetiteCaps() const
{
    if (m_supportsPetiteCaps == SupportsFeature::Unknown) {
        BitVector glyphsSupportedByPetiteCaps;
        RetainPtr ctFont = this->ctFont();
        injectOpenTypeCoverage(CFSTR("pcap"), ctFont.get(), glyphsSupportedByPetiteCaps);
        injectTrueTypeCoverage(kLowerCaseType, kLowerCasePetiteCapsSelector, ctFont.get(), glyphsSupportedByPetiteCaps);
        m_supportsPetiteCaps = glyphsSupportedByPetiteCaps.isEmpty() ? SupportsFeature::No : SupportsFeature::Yes;
    }
    return m_supportsPetiteCaps == SupportsFeature::Yes;
}

bool Font::supportsAllPetiteCaps() const
{
    if (m_supportsAllPetiteCaps == SupportsFeature::Unknown) {
        BitVector glyphsSupportedByAllPetiteCaps;
        RetainPtr ctFont = this->ctFont();
        injectOpenTypeCoverage(CFSTR("pcap"), ctFont.get(), glyphsSupportedByAllPetiteCaps);
        injectOpenTypeCoverage(CFSTR("c2pc"), ctFont.get(), glyphsSupportedByAllPetiteCaps);
        injectTrueTypeCoverage(kLowerCaseType, kLowerCasePetiteCapsSelector, ctFont.get(), glyphsSupportedByAllPetiteCaps);
        injectTrueTypeCoverage(kUpperCaseType, kUpperCasePetiteCapsSelector, ctFont.get(), glyphsSupportedByAllPetiteCaps);
        m_supportsAllPetiteCaps = glyphsSupportedByAllPetiteCaps.isEmpty() ? SupportsFeature::No : SupportsFeature::Yes;
    }
    return m_supportsAllPetiteCaps == SupportsFeature::Yes;
}

static RefPtr<Font> createDerivativeFont(CTFontRef font, float size, FontOrientation orientation, CTFontSymbolicTraits fontTraits, bool syntheticBold, bool syntheticItalic, FontWidthVariant fontWidthVariant, TextRenderingMode textRenderingMode, const FontCustomPlatformData* customPlatformData)
{
    if (!font)
        return nullptr;

    if (syntheticBold)
        fontTraits |= kCTFontBoldTrait;
    if (syntheticItalic)
        fontTraits |= kCTFontItalicTrait;

    CTFontSymbolicTraits scaledFontTraits = CTFontGetSymbolicTraits(font);

    bool usedSyntheticBold = (fontTraits & kCTFontBoldTrait) && !(scaledFontTraits & kCTFontTraitBold);
    bool usedSyntheticOblique = (fontTraits & kCTFontItalicTrait) && !(scaledFontTraits & kCTFontTraitItalic);
    FontPlatformData scaledFontData(font, size, usedSyntheticBold, usedSyntheticOblique, orientation, fontWidthVariant, textRenderingMode, customPlatformData);

    return Font::create(scaledFontData);
}

static inline bool isOpenTypeFeature(CFDictionaryRef feature)
{
    return CFDictionaryContainsKey(feature, kCTFontOpenTypeFeatureTag) && CFDictionaryContainsKey(feature, kCTFontOpenTypeFeatureValue);
}

static inline bool isTrueTypeFeature(CFDictionaryRef feature)
{
    return CFDictionaryContainsKey(feature, kCTFontFeatureTypeIdentifierKey) && CFDictionaryContainsKey(feature, kCTFontFeatureSelectorIdentifierKey);
}

static inline std::optional<CFStringRef> openTypeFeature(CFDictionaryRef feature)
{
    ASSERT(isOpenTypeFeature(feature));
    RetainPtr tag = static_cast<CFStringRef>(CFDictionaryGetValue(feature, kCTFontOpenTypeFeatureTag));
    int rawValue;
    RetainPtr value = static_cast<CFNumberRef>(CFDictionaryGetValue(feature, kCTFontOpenTypeFeatureValue));
    auto success = CFNumberGetValue(value.get(), kCFNumberIntType, &rawValue);
    ASSERT_UNUSED(success, success);
    return rawValue ? std::optional<CFStringRef>(tag.get()) : std::nullopt;
}

static inline std::pair<int, int> trueTypeFeature(CFDictionaryRef feature)
{
    ASSERT(isTrueTypeFeature(feature));
    int rawType;
    RetainPtr type = static_cast<CFNumberRef>(CFDictionaryGetValue(feature, kCTFontFeatureTypeIdentifierKey));
    auto success = CFNumberGetValue(type.get(), kCFNumberIntType, &rawType);
    ASSERT_UNUSED(success, success);
    int rawSelector;
    RetainPtr selector = static_cast<CFNumberRef>(CFDictionaryGetValue(feature, kCTFontFeatureSelectorIdentifierKey));
    success = CFNumberGetValue(selector.get(), kCFNumberIntType, &rawSelector);
    ASSERT_UNUSED(success, success);
    return std::make_pair(rawType, rawSelector);
}

static inline CFNumberRef defaultSelectorForTrueTypeFeature(int key, CTFontRef font)
{
    RetainPtr<CFArrayRef> features = adoptCF(CTFontCopyFeatures(font));
    CFIndex featureCount = CFArrayGetCount(features.get());
    for (CFIndex i = 0; i < featureCount; ++i) {
        RetainPtr featureType = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(features.get(), i));
        RetainPtr featureKey = static_cast<CFNumberRef>(CFDictionaryGetValue(featureType.get(), kCTFontFeatureTypeIdentifierKey));
        if (!featureKey)
            continue;
        int rawFeatureKey;
        CFNumberGetValue(featureKey.get(), kCFNumberIntType, &rawFeatureKey);
        if (rawFeatureKey != key)
            continue;

        RetainPtr featureSelectors = static_cast<CFArrayRef>(CFDictionaryGetValue(featureType.get(), kCTFontFeatureTypeSelectorsKey));
        if (!featureSelectors)
            continue;
        CFIndex selectorsCount = CFArrayGetCount(featureSelectors.get());
        for (CFIndex j = 0; j < selectorsCount; ++j) {
            RetainPtr featureSelector = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(featureSelectors.get(), j));
            RetainPtr isDefault = static_cast<CFNumberRef>(CFDictionaryGetValue(featureSelector.get(), kCTFontFeatureSelectorDefaultKey));
            if (!isDefault)
                continue;
            int rawIsDefault;
            CFNumberGetValue(isDefault.get(), kCFNumberIntType, &rawIsDefault);
            if (!rawIsDefault)
                continue;
            return static_cast<CFNumberRef>(CFDictionaryGetValue(featureSelector.get(), kCTFontFeatureSelectorIdentifierKey));
        }
    }
    return nullptr;
}

static inline RetainPtr<CFDictionaryRef> removedFeature(CFDictionaryRef feature, CTFontRef font)
{
    bool isOpenType = isOpenTypeFeature(feature);
    bool isTrueType = isTrueTypeFeature(feature);
    if (!isOpenType && !isTrueType)
        return feature; // We don't understand this font format.
    RetainPtr<CFMutableDictionaryRef> result = adoptCF(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    if (isOpenType) {
        auto featureTag = openTypeFeature(feature);
        if (featureTag && (CFEqual(featureTag.value(), CFSTR("smcp"))
            || CFEqual(featureTag.value(), CFSTR("c2sc"))
            || CFEqual(featureTag.value(), CFSTR("pcap"))
            || CFEqual(featureTag.value(), CFSTR("c2pc")))) {
            int rawZero = 0;
            RetainPtr<CFNumberRef> zero = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &rawZero));
            CFDictionaryAddValue(result.get(), kCTFontOpenTypeFeatureTag, featureTag.value());
            CFDictionaryAddValue(result.get(), kCTFontOpenTypeFeatureValue, zero.get());
        } else {
            CFDictionaryAddValue(result.get(), kCTFontOpenTypeFeatureTag, CFDictionaryGetValue(feature, kCTFontOpenTypeFeatureTag));
            CFDictionaryAddValue(result.get(), kCTFontOpenTypeFeatureValue, CFDictionaryGetValue(feature, kCTFontOpenTypeFeatureValue));
        }
    }
    if (isTrueType) {
        auto trueTypeFeaturePair = trueTypeFeature(feature);
        if (trueTypeFeaturePair.first == kLowerCaseType && (trueTypeFeaturePair.second == kLowerCaseSmallCapsSelector || trueTypeFeaturePair.second == kLowerCasePetiteCapsSelector)) {
            CFDictionaryAddValue(result.get(), kCTFontFeatureTypeIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureTypeIdentifierKey));
            if (RetainPtr defaultSelector = defaultSelectorForTrueTypeFeature(kLowerCaseType, font))
                CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, defaultSelector.get());
            else
                CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureSelectorIdentifierKey));
        } else if (trueTypeFeaturePair.first == kUpperCaseType && (trueTypeFeaturePair.second == kUpperCaseSmallCapsSelector || trueTypeFeaturePair.second == kUpperCasePetiteCapsSelector)) {
            CFDictionaryAddValue(result.get(), kCTFontFeatureTypeIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureTypeIdentifierKey));
            if (RetainPtr defaultSelector = defaultSelectorForTrueTypeFeature(kUpperCaseType, font))
                CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, defaultSelector.get());
            else
                CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureSelectorIdentifierKey));
        } else {
            CFDictionaryAddValue(result.get(), kCTFontFeatureTypeIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureTypeIdentifierKey));
            CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureSelectorIdentifierKey));
        }
    }
    return result;
}

static RetainPtr<CTFontRef> createCTFontWithoutSynthesizableFeatures(CTFontRef font)
{
    RetainPtr<CFArrayRef> features = adoptCF(static_cast<CFArrayRef>(CTFontCopyAttribute(font, kCTFontFeatureSettingsAttribute)));
    if (!features)
        return font;
    CFIndex featureCount = CFArrayGetCount(features.get());
    RetainPtr<CFMutableArrayRef> newFeatures = adoptCF(CFArrayCreateMutable(kCFAllocatorDefault, featureCount, &kCFTypeArrayCallBacks));
    for (CFIndex i = 0; i < featureCount; ++i) {
        RetainPtr feature = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(features.get(), i));
        CFArrayAppendValue(newFeatures.get(), removedFeature(feature.get(), font).get());
    }
    CFTypeRef keys[] = { kCTFontFeatureSettingsAttribute };
    CFTypeRef values[] = { newFeatures.get() };
    RetainPtr<CFDictionaryRef> attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    RetainPtr<CTFontDescriptorRef> newDescriptor = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
    return adoptCF(CTFontCreateCopyWithAttributes(font, CTFontGetSize(font), nullptr, newDescriptor.get()));
}

RefPtr<Font> Font::createFontWithoutSynthesizableFeatures() const
{
    float size = m_platformData.size();
    RetainPtr ctFont = this->ctFont();
    CTFontSymbolicTraits fontTraits = CTFontGetSymbolicTraits(ctFont.get());
    RetainPtr newCTFont = createCTFontWithoutSynthesizableFeatures(ctFont.get());
    return createDerivativeFont(newCTFont.get(), size, m_platformData.orientation(), fontTraits, m_platformData.syntheticBold(), m_platformData.syntheticOblique(), m_platformData.widthVariant(), m_platformData.textRenderingMode(), protect(m_platformData.customPlatformData()).get());
}

RefPtr<Font> Font::platformCreateScaledFont(const FontDescription&, float scaleFactor) const
{
    float size = m_platformData.size() * scaleFactor;
    RetainPtr ctFont = this->ctFont();
    CTFontSymbolicTraits fontTraits = CTFontGetSymbolicTraits(ctFont.get());
    RetainPtr<CTFontDescriptorRef> fontDescriptor = adoptCF(CTFontCopyFontDescriptor(ctFont.get()));
    RetainPtr<CTFontRef> scaledFont = adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor.get(), size, nullptr));

    return createDerivativeFont(scaledFont.get(), size, m_platformData.orientation(), fontTraits, m_platformData.syntheticBold(), m_platformData.syntheticOblique(), m_platformData.widthVariant(), m_platformData.textRenderingMode(), protect(m_platformData.customPlatformData()).get());
}

bool supportsOpenTypeFeature(CTFontRef font, CFStringRef featureTag)
{
    RetainPtr<CFArrayRef> features = adoptCF(CTFontCopyFeatures(font));
    CFIndex featureCount = CFArrayGetCount(features.get());
    for (CFIndex featureIndex = 0; featureIndex < featureCount; ++featureIndex) {
        RetainPtr feature = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(features.get(), featureIndex));
        RetainPtr featureTypeIdentifier = static_cast<CFNumberRef>(CFDictionaryGetValue(feature.get(), kCTFontFeatureTypeIdentifierKey));
        if (!featureTypeIdentifier)
            continue;

        int rawFeatureTypeIdentifier;
        CFNumberGetValue(featureTypeIdentifier.get(), kCFNumberIntType, &rawFeatureTypeIdentifier);
        if (rawFeatureTypeIdentifier != kTextSpacingType)
            continue;

        RetainPtr featureSelectors = static_cast<CFArrayRef>(CFDictionaryGetValue(feature.get(), kCTFontFeatureTypeSelectorsKey));
        if (!featureSelectors)
            continue;
        auto selectorsCount = CFArrayGetCount(featureSelectors.get());
        for (CFIndex selectorIndex = 0; selectorIndex < selectorsCount; ++selectorIndex) {
            RetainPtr featureSelector = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(featureSelectors.get(), selectorIndex));
            RetainPtr openTypeTag = static_cast<CFStringRef>(CFDictionaryGetValue(featureSelector.get(), kCTFontOpenTypeFeatureTag));
            if (!openTypeTag)
                continue;
            if (CFStringCompare(openTypeTag.get(), featureTag, 0) == kCFCompareEqualTo)
                return true;
        }
    }
    return false;
}

RefPtr<Font> Font::platformCreateHalfWidthFont() const
{
    if (!supportsOpenTypeAlternateHalfWidths())
        return nullptr;

    RetainPtr ctFont = this->ctFont();
    RetainPtr<CTFontDescriptorRef> fontDescriptor = adoptCF(CTFontCopyFontDescriptor(ctFont.get()));
    auto size = m_platformData.size();
    auto fontTraits = CTFontGetSymbolicTraits(ctFont.get());
    int enableHaltValue = 1;
    auto featureName = CFSTR("halt");
    auto featureValue = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &enableHaltValue));

    const void* featureValues[] = { featureName, featureValue.get() };
    auto fontFeatureSettings = adoptCF(CFArrayCreate(kCFAllocatorDefault, featureValues, std::size(featureValues), &kCFTypeArrayCallBacks));

    CFTypeRef fontDescriptorKeys[] = { kCTFontFeatureSettingsAttribute };
    CFTypeRef fontDescriptorValues[] = { fontFeatureSettings.get() };
    auto attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, fontDescriptorKeys, fontDescriptorValues, std::size(fontDescriptorValues), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));

    auto attributesDescriptor = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
    auto halfWidthFont = adoptCF(CTFontCreateCopyWithAttributes(ctFont.get(), size, nullptr, attributesDescriptor.get()));

    return createDerivativeFont(halfWidthFont.get(), size, m_platformData.orientation(), fontTraits, m_platformData.syntheticBold(), m_platformData.syntheticOblique(), m_platformData.widthVariant(), m_platformData.textRenderingMode(), protect(m_platformData.customPlatformData()).get());
}

float Font::platformWidthForGlyph(Glyph glyph) const
{
    CGSize advance = CGSizeZero;

    if (platformData().size()) {
        bool horizontal = platformData().orientation() == FontOrientation::Horizontal;
        CTFontOrientation orientation = horizontal || m_isBrokenIdeographFallback ? kCTFontOrientationHorizontal : kCTFontOrientationVertical;
        CTFontGetAdvancesForGlyphs(protect(ctFont()).get(), orientation, &glyph, &advance, 1);
    }
#if PLATFORM(DRIFTSTACK)
    // 2026-06-27 Kefa Family-A per-glyph advance override (blfonts metricsHash c6bdb116).
    // CSS family "Kefa" aliases to the macOS "Kefa III" face (FontCacheCoreText), whose per-glyph
    // advances differ from real iOS Kefa → the browserleaks 1:1 metric GROUP for Kefa reads
    // ~4155,149 (fork) instead of 4367,149 (real) → divergent grouped metricsHash. Override the
    // resolved "Kefa III" face's probe-string glyph advances to the real-iOS-captured values
    // (DriftstackKefaAdvances.h). Family-A only; on >=26 Kefa is absent so this face never resolves.
    // Reverse-map the glyph→codepoint via CTFontGetGlyphsForCharacters over the 14 probe codepoints
    // only (cheap; the override is a no-op for every other glyph/face → byte-neutral elsewhere).
    if (platformData().size() > 0.f && driftstackKefaAdvancesActive()
        && m_platformData.familyName() == "Kefa III"_s) {
        // Latin probe codepoints PLUS the GCPS chars Kefa III renders in ITS OWN primary face
        // (₹ U+20B9 / ₺ U+20BA / ₸ U+20B8 / ẞ U+1E9E). #4 matrix residual: these have Kefa-III
        // glyphs, so they never route to a fallback run and the fallback-keyed GcpsFallback hook is
        // bypassed → the +27 group overshoot. Resolve each cp → its Kefa-III glyph ID via
        // CTFontGetGlyphsForCharacters here and override to the real iOS advance (Helvetica for ₹/₺/₸,
        // see DriftstackKefaAdvances.h). ▁(U+2581)/ॿ(U+097F) are NOT here — Kefa III lacks those
        // glyphs so they DO fall to a fallback face and stay in DriftstackGcpsFallback.h.
        static constexpr char32_t kKefaProbeCps[] = {
            0x006D, 0x004D, 0x006C, 0x004C, 0x0069, 0x0049, 0x0077, 0x0057,
            0x20B9, 0x20BA, 0x20B8, 0x1E9E
        };
        RetainPtr kefaFont = ctFont();
        if (kefaFont) {
            for (char32_t cp : kKefaProbeCps) {
                UniChar ch[2] = { 0, 0 };
                CGGlyph g[2] = { 0, 0 };
                CFIndex len = 1;
                if (cp > 0xFFFF) {
                    uint32_t scalar = cp - 0x10000;
                    ch[0] = static_cast<UniChar>(0xD800 + (scalar >> 10));
                    ch[1] = static_cast<UniChar>(0xDC00 + (scalar & 0x3FF));
                    len = 2;
                } else
                    ch[0] = static_cast<UniChar>(cp);
                if (CTFontGetGlyphsForCharacters(kefaFont.get(), ch, g, len) && g[0] && g[0] == glyph) {
                    float kefaAdv = 0.f;
                    if (driftstackLookupKefaAdvance(cp, platformData().size(), kefaAdv))
                        return kefaAdv;
                    break;
                }
            }
        }
    }
    // Task #118: the per-glyph V121/V690 width-override HIT + reverse-map-built WTFLogAlways below fire
    // in this HOT path on EVERY ASCII-glyph advance (per-glyph during measureText / DOM text paint) —
    // an os_log side-channel on the critical path that floods logd. Gate them behind DRIFTSTACK_FONT_VERBOSE
    // (default OFF), mirroring the P5 DRIFTSTACK_CANVAS_VERBOSE pattern. Byte-neutral: logging never touches
    // a returned advance; the override values are unchanged.
    static bool s_dsFontVerbose = []() {
        const char* env = getenv("DRIFTSTACK_FONT_VERBOSE");
        return env && env[0] == '1';
    }();
    // P-#48.I Wave 29-323 diag: when DRIFTSTACK_V433Z_GLYPH_DIAG=1, log
    // the advance Mac returns for our 10 V-433.Z target codepoints'
    // glyphs (capped at 30 fires per process to avoid log flood).
    // Pinpoints which (font, ptSize, cp) Mac returns 0/wrong advance for,
    // driving Mn-category override design (closure path per wave 29-322).
    static bool s_v433zGlyphDiagEnabled = []() {
        const char* env = getenv("DRIFTSTACK_V433Z_GLYPH_DIAG");
        return env && env[0] == '1';
    }();
    if (s_v433zGlyphDiagEnabled && platformData().size() > 0) {
        static const std::array<char32_t, 10> kTargetCps {
            0x1CDA, 0x17DD, 0x302E, 0x2C7B, 0x10A0,
            0xA73D, 0xFFFD, 0x21E4, 0x20E3, 0x20B9
        };
        RetainPtr<CTFontRef> font = ctFont();
        for (auto cp : kTargetCps) {
            UniChar ch[2] = { 0 };
            CGGlyph cpGlyph[2] = { 0 };
            CFIndex len = 1;
            if (cp > 0xFFFF) {
                uint32_t scalar = cp - 0x10000;
                ch[0] = 0xD800 | (scalar >> 10);
                ch[1] = 0xDC00 | (scalar & 0x3FF);
                len = 2;
            } else {
                ch[0] = static_cast<UniChar>(cp);
            }
            if (CTFontGetGlyphsForCharacters(font.get(), ch, cpGlyph, len) && cpGlyph[0] == glyph) {
                static unsigned diagCount = 0;
                if (diagCount++ < 30) {
                    RetainPtr<CFStringRef> family = adoptCF(CTFontCopyFamilyName(font.get()));
                    WTFLogAlways("[Driftstack-V433Z-GlyphAdv] cp=U+%04X font='%s' ptSize=%.1f advance=%.3f",
                        (unsigned)cp,
                        family ? String(family.get()).utf8().data() : "(null)",
                        platformData().size(), advance.width);
                }
                break;
            }
        }
    }

    // P-#48.J Wave 29-324: Mn-category advance override.
    // iPhone synthesizes non-zero advance for standalone combining marks
    // (U+1CDA, U+20E3 in our V-433.Z target list). Mac returns 0 per
    // Unicode spec. Override to iPhone-canonical advance (ptSize-scaled
    // from reference 72pt: U+1CDA=27→0.375, U+20E3=72→1.0).
    // Env-gated DRIFTSTACK_V433Z_MN_OVERRIDE=1 for staged rollout.
    static bool s_v433zMnOverrideEnabled = []() {
        const char* env = getenv("DRIFTSTACK_V433Z_MN_OVERRIDE");
        return env && env[0] == '1';
    }();
    if (s_v433zMnOverrideEnabled && platformData().size() > 0) {
        RetainPtr<CTFontRef> font = ctFont();
        // Check if glyph matches U+1CDA or U+20E3 in this font
        const struct { char32_t cp; float ratio; } kMnOverrides[] = {
            { 0x1CDA, 27.0f / 72.0f },  // Vedic Sign Three Dots Above
            { 0x20E3, 72.0f / 72.0f },  // Combining Enclosing Keycap
        };
        for (const auto& o : kMnOverrides) {
            UniChar ch[2] = { 0 };
            CGGlyph cpGlyph[2] = { 0 };
            CFIndex len = 1;
            if (o.cp > 0xFFFF) {
                uint32_t scalar = o.cp - 0x10000;
                ch[0] = 0xD800 | (scalar >> 10);
                ch[1] = 0xDC00 | (scalar & 0x3FF);
                len = 2;
            } else {
                ch[0] = static_cast<UniChar>(o.cp);
            }
            if (CTFontGetGlyphsForCharacters(font.get(), ch, cpGlyph, len) && cpGlyph[0] == glyph) {
                float synthAdvance = o.ratio * platformData().size();
                static unsigned mnLogCount = 0;
                if (mnLogCount++ < 20) {
                    WTFLogAlways("[Driftstack-V433Z-MnOverride] cp=U+%04X ptSize=%.1f mac=%.3f → synth=%.3f",
                        (unsigned)o.cp, platformData().size(), advance.width, synthAdvance);
                }
                return synthAdvance;
            }
        }
    }
    // The seven single-scalar Emoji 17 additions can take the simple one-glyph
    // path. Their UI-context font is bundled face1, whose directly materialized
    // advance loses hidden-UI tracking. Restore the host UI proxy here. Exact
    // multi-glyph clusters bypass this per-glyph hook in ComplexTextController,
    // so their zero overlays remain protected by cluster-level normalization.
    if (platformData().size() > 0.f
        && driftstackIsBundledAppleColorEmojiUIFont(ctFont())
        && colorGlyphType(glyph) == ColorGlyphType::Color) {
        auto geometry = driftstackSystemEmojiUIGeometry(platformData().size());
        if (geometry)
            return geometry.advance;
    }

    // V-094 Track 5: iPhone Apple Color Emoji advance is constant per
    // ptSize across all emoji codepoints. Empirical (Track 5 capture
    // 159 probes / 53 codepoints / 3 sizes):
    //   ptSize 14 → advance 19
    //   ptSize 24 → advance 25
    //   ptSize 48 → advance 48
    // Override Mac CTFontGetAdvancesForGlyphs result for color glyphs
    // so canvas.measureText returns iPhone-equivalent widths.
    if (platformData().size() > 0.f
        && m_platformData.familyName() == "Apple Color Emoji"_s
        && colorGlyphType(glyph) == ColorGlyphType::Color) {
        const float ptSize = platformData().size();
        // W554 (2026-06-03): EXACT real iPhone 17 Apple Color Emoji measureText advance, captured
        // across the FULL V-405 fuzzer size set (BS /emoji-advance-curve, uniform across all emoji):
        // advance == ptSize for size >= 26 (26->26 .. 72->72), and a strike floor below
        // {12:16,14:19,16:21,18:22,20:23,22:24,24:25}. The old V-094 code linearly interpolated the
        // 24->48 segment (25->48) from only 3 captured points (14/24/48) — which yielded 32.67 @32px
        // (the OPEN closelist emoji item). The real curve is FLAT (ratio 1.0) from 26 up, so 32 -> 32.
        return driftstackPublicAppleColorEmojiAdvance(ptSize);
    }

    // V-145: Apple Color Emoji has a SPACE glyph (U+0020) at width 19/21/22/23/25
    // for sizes 14/16/18/20/24 (per stage-f-emoji-ascii capture). Mac CT
    // returns ~3.89 (Helvetica fallback width) which causes the cumulative-rig
    // Apple Color Emoji probe 5px diff. Override Apple Color Emoji's space
    // glyph specifically.
    if (platformData().size() > 0.f) {
        const auto& familyName = m_platformData.familyName();
        if (familyName == "Apple Color Emoji"_s || familyName == ".Apple Color Emoji UI"_s) {
            // V-145 + W588 (2026-06-04): Apple Color Emoji renders the keycap-base characters
            // — space (U+0020), '#' (U+0023), '*' (U+002A) and digits '0'-'9' (U+0030..U+0039),
            // the bases of the keycap-emoji sequences (0️⃣..9️⃣ #️⃣ *️⃣) — at the Apple Color Emoji
            // STRIKE advance, NOT the glyph's natural width. Real iPhone-17 / Safari 26.4, W587
            // full-surface (10 /aio refs, 86 size×char keys): {10:13,12:16,14:19,16:21,18:22,
            // 20:23,22:24,24:25}, == ptSize for >=26. The Mac fork returned the natural (~ptSize)
            // advance → an 86-key measureText divergence (atlas-work-queue item 2; NOT closed by
            // the W554 emoji block, since bare digits are not color glyphs). Other ASCII (+ - and
            // letters) is Arial-resolved and already matches, so the override is scoped to the
            // keycap-base set. (Widens the old space-only block — which covered just 14/16/18/20/24
            // — to the full keycap set AND the previously-missing 10/12/22 sizes.)
            static const UniChar kKeycapBase[] = {
                0x20, 0x23, 0x2A, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39
            };
            RetainPtr keycapFont = ctFont();
            bool isKeycapBase = false;
            for (UniChar kc : kKeycapBase) {
                CGGlyph g = 0;
                if (CTFontGetGlyphsForCharacters(keycapFont.get(), &kc, &g, 1) && g && g == glyph) {
                    isKeycapBase = true;
                    break;
                }
            }
            if (isKeycapBase) {
                const float ptSize = platformData().size();
                const unsigned ptPx = static_cast<unsigned>(ptSize + 0.5f);
                if (ptPx >= 26)
                    return ptSize;
                switch (ptPx) {
                    case 10: return 13.f;
                    case 12: return 16.f;
                    case 14: return 19.f;
                    case 16: return 21.f;
                    case 18: return 22.f;
                    case 20: return 23.f;
                    case 22: return 24.f;
                    case 24: return 25.f;
                    default: return ptSize <= 12.f ? 16.f * (ptSize / 12.f) : ptSize;
                }
            }
        }
    }

    // V-121 closure: per-glyph ASCII advance override at the configured
    // (font, size, codepoint) combinations. iPhone reference data captured
    // via stage-f-ascii-advances probe (1900 entries × 4 fonts × 5 sizes ×
    // 95 codepoints). Mac CT advance differs from iPhone CT advance by ~0.18 px/char
    // for -apple-system + ~0.45 px/char for sans-serif fallback, accumulating
    // to the cumulative-rig measureText.fonts.value.{-apple-system,Apple Color
    // Emoji}.width residuals (V-120/V-121). This override aligns advances to
    // iPhone reference, which closes the residual + helps the canvas-fp t02
    // multi-glyph composition match.
    if (platformData().size() > 0.f) {
        const float ptSize = platformData().size();
        const uint16_t sizePx = static_cast<uint16_t>(roundf(ptSize));
        // V-688 (2026-05-11): extend size range to all V-405 fuzzer sizes 12-48
        // (was 5 specific sizes: 14/16/18/20/24). Non-ASCII table covers a subset
        // (13 even sizes 12,14,...,48); the per-script fallback below handles
        // missing-size case by simply returning Mac CT's natural advance.
        // V-433.Z wave 29-210: extend to 72 to include the Phase 2 unicode-glyphs
        // probe font-size (V-689 atlas extension at sizePx=72 for fallback fonts).
        if (sizePx >= 12 && sizePx <= 72) {
            // Map resolved family name → atlas-table key. Direct CSS-name
            // matches first (Arial, Helvetica, Times New Roman, Courier,
            // Tahoma, Verdana, Georgia, Trebuchet MS — priority D coverage).
            // Then generic-resolution aliases (Mac per-page-settings defaults
            // for sans-serif/serif/etc. → V-122 multi-key pattern).
            const String& familyName = m_platformData.familyName();
            const char* atlasKey = nullptr;
            if (familyName == "Arial"_s) atlasKey = "Arial";
            else if (familyName == "Tahoma"_s) atlasKey = "Tahoma";
            else if (familyName == "Times New Roman"_s) atlasKey = "Times New Roman";
            else if (familyName == "Courier"_s || familyName == "Courier New"_s) atlasKey = "Courier";
            else if (familyName == "Verdana"_s) atlasKey = "Verdana";
            else if (familyName == "Georgia"_s) atlasKey = "Georgia";
            else if (familyName == "Trebuchet MS"_s) atlasKey = "Trebuchet MS";
            else if (familyName == "Helvetica"_s) atlasKey = "Helvetica";
            else if (familyName == ".AppleSystemUIFont"_s) atlasKey = "-apple-system";
            else if (familyName == "Times"_s || familyName == "Times Roman"_s) atlasKey = "serif";
            // V-144: Mac resolves CSS generic keywords to internal -webkit-*
            // names (per V-138 instrumentation). Add fallbacks.
            else if (familyName == "-webkit-sans-serif"_s) atlasKey = "sans-serif";
            else if (familyName == "-webkit-serif"_s) atlasKey = "serif";
            else if (familyName == "-webkit-system-font"_s) atlasKey = "system-ui";
            // V-433.Z wave 29-210: universal-symbol cluster fallback fonts
            // routed by driftstackIOSFallbackFontForUniversalSymbolCluster hook.
            // Mac CT family names (canonical via mdls kCTFontFamilyNameAttribute).
            else if (familyName == ".SF Devanagari"_s) atlasKey = ".SF Devanagari";
            else if (familyName == ".SF Georgian"_s) atlasKey = ".SF Georgian";
            else if (familyName == ".SF UI Symbols"_s) atlasKey = ".SF UI Symbols";
            else if (familyName == ".SF UI"_s) atlasKey = ".SF UI";
            else if (familyName == "Apple Symbols"_s) atlasKey = "Apple Symbols";
            // V-433.Z wave 29-211: Mac CT cascade resolves Vedic / Devanagari /
            // Khmer / Indian Rupee codepoints to Mac-system fallback families
            // (.AppleIndicFont, Kohinoor*, Khmer Sangam MN, Mukta Mahee) instead
            // of routing through V-433.Z hook's .SF Devanagari result. Alias
            // these Mac fallback families to the same atlas key the iPhone-
            // canonical font uses, so the V-689 atlas substitutes iPhone widths
            // regardless of which fallback Mac picks.
            else if (familyName == ".AppleIndicFont"_s
                  || familyName == "Kohinoor Devanagari"_s
                  || familyName == "Kohinoor Bangla"_s
                  || familyName == "Kohinoor Gujarati"_s
                  || familyName == "Kohinoor Telugu"_s
                  || familyName == "Mukta Mahee"_s
                  || familyName == "Devanagari Sangam MN"_s
                  || familyName == ".SF Bangla"_s
                  || familyName == ".SF Gujarati"_s
                  || familyName == ".SF Gurmukhi"_s
                  || familyName == ".SF Kannada"_s
                  || familyName == ".SF Malayalam"_s
                  || familyName == ".SF Odia"_s
                  || familyName == ".SF Tamil"_s
                  || familyName == ".SF Telugu"_s
                  || familyName == "Tamil Sangam MN"_s
                  || familyName == "Sinhala Sangam MN"_s
                  || familyName == "Malayalam Sangam MN"_s
                  || familyName == "Noto Sans Kannada"_s
                  || familyName == "Noto Sans Oriya"_s) atlasKey = ".SF Devanagari";
            else if (familyName == "Khmer Sangam MN"_s
                  || familyName == ".Apple Symbols Fallback"_s
                  || familyName == ".AppleSystemFallback"_s
                  || familyName == "Lao Sangam MN"_s
                  || familyName == "Noto Sans Myanmar"_s
                  || familyName == "Noto Sans Zawgyi"_s
                  || familyName == ".ThonburiUI"_s
                  || familyName == "Kokonor"_s) atlasKey = "Apple Symbols";
            else if (familyName == "Noto Sans Armenian"_s
                  || familyName == ".SF Armenian"_s) atlasKey = ".SF Georgian";  // Armenian/Georgian closely-related
            // V-691 REVERTED (2026-05-11): script-fallback aliasing (CJK/Arabic/Devanagari
            // families → atlasKey="-apple-system" with script-scoped reverse maps)
            // regressed V-405 atlas-OFF text from 1/249 → 0/249. Empirically: Mac's
            // native script-fallback rendering ALREADY coincidentally matches iPhone
            // for some seeds (e.g. text/206 mixing CJK+Devanagari+Arabic — V-687 single-
            // glyph alpha-diff=0). Overriding widths to iOS apple-system values mixes
            // Mac-shape-bytes with iOS-position-positioning → destroys the coincidental
            // match. Width overrides only help if Mac uses a DIFFERENT FONT than iOS
            // (e.g. Geeza Pro vs SF Arabic), but for fonts with bit-identical HMTX
            // (Mac PingFangUI ↔ iOS PingFang per V-679), widths already match.
            //
            // Closure path: capture per-fallback-font iPhone reference data (e.g. iOS
            // Sangam MN widths), then alias only for fonts where Mac+iOS diverge.
            uint32_t scriptRangeLo = 0;
            uint32_t scriptRangeHi = 0xFFFFFFFFu;
            // V-145 diagnostic: log every (familyName, atlasKey) resolution. Gated default-OFF
            // (W2590): this fired UNCONDITIONALLY on every font resolution — production log spam
            // AND a severe slowdown on broad glyph sweeps (every exotic-codepoint fallback logs),
            // which starved the whole-iPhone DOM-geometry sweep + the 3564-font uniqueMetrics probe.
            if (getenv("DRIFTSTACK_LOG_FONT_RESOLVE"))
                WTFLogAlways("[Driftstack-V145] resolve family='%s' → atlasKey='%s' size=%.1f script=[U+%04X..U+%04X]",
                    familyName.utf8().data(), atlasKey ? atlasKey : "(null)", ptSize, scriptRangeLo, scriptRangeHi);
            if (atlasKey) {
                // Find atlasKey font_id (shared between ASCII + non-ASCII tables).
                uint16_t fontId = 0xFFFF;
                for (uint16_t i = 0; i < std::size(kDriftstackAsciiAdvanceFonts); ++i) {
                    if (kDriftstackAsciiAdvanceFonts[i] == atlasKey) {
                        fontId = i;
                        break;
                    }
                }
                // Build glyph→codepoint reverse map for ASCII + V-688 non-ASCII + V-690 mmap atlas codepoints.
                // V-690 (Wave 25 / 2026-05-11): extends reverse map to include codepoints from
                // the DriftstackAdvanceAtlas binary file (2.7M (font, size, cp) → width entries).
                // Coverage: full V-405 fuzzer codepoint range across 5 scripts × 37 sizes × 6 fonts.
                //
                // Task #118: the reverse map content depends ONLY on (fontId, sizePx, scriptRange) — the
                // glyph→codepoint mapping for a given atlas font binary at a given size is identical across
                // EVERY Font wrapper instance. Building it was a PER-INSTANCE ~2ms cost (12k+ CTFontGetGlyphs
                // calls per atlas range), and a page that creates many Font instances for the same
                // (atlasKey,size) — e.g. the timing-fp HUD re-rendering .AppleSystemUIFont@12 five times —
                // paid that cost repeatedly. Those redundant cold builds landed inside the a.j 55-font probe's
                // setTimeout-sliced wall-clock → a.j measured ~220ms vs the iPhone's ~117ms. Memoize the built
                // map in a process-global cache keyed by (fontId,sizePx,scriptRange): the FIRST Font builds it;
                // every later Font with the same key copies it (a HashMap copy, microseconds) instead of
                // rebuilding. Byte-identical: the copied map has the exact entries the per-instance build would
                // produce (same font binary, same CT glyph IDs) — zero fingerprint-value change; removes CPU only.
                using DSReverseMap = HashMap<unsigned, char32_t, IntHash<unsigned>, WTF::UnsignedWithZeroKeyHashTraits<unsigned>>;
                static Lock s_dsReverseMapCacheLock;
                static NeverDestroyed<HashMap<uint64_t, DSReverseMap>> s_dsReverseMapCache;
                // Key MUST capture everything the built map's glyph IDs depend on so two Fonts only share a map
                // when their CTFonts are glyph-identical: the RESOLVED family name (distinguishes e.g. "Courier"
                // vs "Courier New" — same atlasKey/fontId but DIFFERENT font binaries / cmaps → different glyph
                // IDs), sizePx, scriptRange, AND bold/italic (synthetic-or-real → a different CTFont). A mismatch
                // would mis-map glyph→cp → a wrong width override → a fingerprint change, so the key is exact.
                CTFontSymbolicTraits dsKeyTraits = ctFont() ? CTFontGetSymbolicTraits(ctFont()) : 0;
                uint64_t dsStyleBits = (((dsKeyTraits & kCTFontTraitBold) || m_platformData.syntheticBold()) ? 1u : 0u)
                    | (((dsKeyTraits & kCTFontTraitItalic) || m_platformData.syntheticOblique()) ? 2u : 0u);
                uint64_t cacheKey = (static_cast<uint64_t>(m_platformData.familyName().hash()) << 32)
                    ^ (dsStyleBits << 30)
                    ^ (static_cast<uint64_t>(sizePx & 0xFFFF) << 16)
                    ^ (static_cast<uint64_t>(scriptRangeLo & 0xFF) << 8)
                    ^ (static_cast<uint64_t>(scriptRangeHi == 0xFFFFFFFFu ? 1u : (scriptRangeHi & 0xFF)));
                if (!m_driftstackAsciiReverseMapBuilt && fontId != 0xFFFF) {
                    Locker locker(s_dsReverseMapCacheLock);
                    auto cached = s_dsReverseMapCache->find(cacheKey);
                    if (cached != s_dsReverseMapCache->end()) {
                        m_driftstackAsciiReverseMap = cached->value;
                        m_driftstackAsciiReverseMapBuilt = true;
                    }
                }
                if (!m_driftstackAsciiReverseMapBuilt) {
                    RetainPtr font = ctFont();
                    if (font) {
                        // ASCII range U+0020..U+007E (skipped when scriptRange excludes ASCII —
                        // e.g. script-fallback Font instances shouldn't override ASCII).
                        if (scriptRangeLo <= 0x20 && scriptRangeHi >= 0x7E) {
                            for (UChar cp = 0x20; cp <= 0x7E; ++cp) {
                                UniChar ch[1] = { cp };
                                CGGlyph glyphs[1] = { 0 };
                                if (CTFontGetGlyphsForCharacters(font.get(), ch, glyphs, 1) && glyphs[0])
                                    m_driftstackAsciiReverseMap.set(glyphs[0], static_cast<char32_t>(cp));
                            }
                        }
                        if (fontId != 0xFFFF) {
                            // V-688: non-ASCII constexpr table (CJK 152 + Arabic 60 + Devanagari 70).
                            // V-691: scope to scriptRange for fallback fonts.
                            for (const auto& e : kDriftstackNonAsciiAdvanceTable) {
                                if (e.fontId > fontId)
                                    break;
                                if (e.fontId != fontId)
                                    continue;
                                char32_t cp = static_cast<char32_t>(e.codepoint);
                                if (cp < scriptRangeLo || cp > scriptRangeHi)
                                    continue;
                                if (cp < 0x10000) {
                                    UniChar ch[1] = { static_cast<UniChar>(cp) };
                                    CGGlyph g[1] = { 0 };
                                    if (CTFontGetGlyphsForCharacters(font.get(), ch, g, 1) && g[0])
                                        m_driftstackAsciiReverseMap.set(g[0], cp);
                                } else {
                                    UniChar ch[2] = {
                                        static_cast<UniChar>(0xD800 + ((cp - 0x10000) >> 10)),
                                        static_cast<UniChar>(0xDC00 + ((cp - 0x10000) & 0x3FF))
                                    };
                                    CGGlyph g[2] = { 0, 0 };
                                    if (CTFontGetGlyphsForCharacters(font.get(), ch, g, 2) && g[0])
                                        m_driftstackAsciiReverseMap.set(g[0], cp);
                                }
                            }
                            // V-690: also iterate DriftstackAdvanceAtlas entries for (fontId, sizePx).
                            // The atlas covers ~12k codepoints per (font, size) → 12k CTFontGetGlyphsForCharacters
                            // calls, ~100ms first-access cost amortized to subsequent lookups.
                            const auto& atlas = DriftstackAdvanceAtlas::singleton();
                            WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
                            if (atlas.isAvailable()) {
                                uint32_t atlasCount = 0;
                                const DriftstackAdvanceEntry* atlasEntries = atlas.entriesForFontSize(fontId, sizePx, &atlasCount);
                                if (atlasEntries) {
                                    for (uint32_t i = 0; i < atlasCount; ++i) {
                                        char32_t cp = static_cast<char32_t>(atlasEntries[i].codepoint);
                                        if (cp < scriptRangeLo || cp > scriptRangeHi)
                                            continue;
                                        if (m_driftstackAsciiReverseMap.contains(cp))
                                            continue;
                                        if (cp < 0x10000) {
                                            UniChar ch[1] = { static_cast<UniChar>(cp) };
                                            CGGlyph g[1] = { 0 };
                                            if (CTFontGetGlyphsForCharacters(font.get(), ch, g, 1) && g[0])
                                                m_driftstackAsciiReverseMap.set(g[0], cp);
                                        } else {
                                            UniChar ch[2] = {
                                                static_cast<UniChar>(0xD800 + ((cp - 0x10000) >> 10)),
                                                static_cast<UniChar>(0xDC00 + ((cp - 0x10000) & 0x3FF))
                                            };
                                            CGGlyph g[2] = { 0, 0 };
                                            if (CTFontGetGlyphsForCharacters(font.get(), ch, g, 2) && g[0])
                                                m_driftstackAsciiReverseMap.set(g[0], cp);
                                        }
                                    }
                                    static unsigned builtCount = 0;
                                    if (++builtCount <= 8)
                                        WTFLogAlways("[Driftstack-V690] atlas range loaded for fontId=%u size=%u: %u atlas cps → reverse map total %u",
                                            fontId, sizePx, atlasCount, static_cast<unsigned>(m_driftstackAsciiReverseMap.size()));
                                }
                            }
                            WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
                        }
                    }
                    m_driftstackAsciiReverseMapBuilt = true;
                    // Task #118: publish this freshly-built map to the process-global cache so the NEXT Font
                    // instance with the same (fontId,sizePx,scriptRange) copies it instead of rebuilding.
                    if (fontId != 0xFFFF) {
                        Locker locker(s_dsReverseMapCacheLock);
                        s_dsReverseMapCache->add(cacheKey, m_driftstackAsciiReverseMap);
                    }
                    if (s_dsFontVerbose)
                        WTFLogAlways("[Driftstack-V121+V688+V690] reverse map built for family='%s' atlasKey='%s' size=%.1f entries=%u",
                            familyName.utf8().data(), atlasKey, ptSize, static_cast<unsigned>(m_driftstackAsciiReverseMap.size()));
                }
                auto it = m_driftstackAsciiReverseMap.find(glyph);
                if (it != m_driftstackAsciiReverseMap.end()) {
                    char32_t cp = it->value;
                    if (fontId != 0xFFFF) {
                        // V-690 styled extension: bold/italic glyph bitmaps are
                        // style-keyed in the DSAS glyph atlas, but advances were
                        // family-only (fontId 0-12) so bold/italic text used the
                        // regular (too-narrow) advance → progressive horizontal drift
                        // (measured ~0.5px/char). Encode style into the advance fontId:
                        // regular 0-12 unchanged; bold +100, italic +200, bold-italic
                        // +300 (styled entries live in DriftstackAdvanceAtlas Tier 2).
                        // Regular path is byte-identical (advFontId == fontId, Tier 1
                        // unchanged) so cumrig schema baseline is preserved.
                        uint16_t styleCode = 0;
                        {
                            CTFontSymbolicTraits dsTraits = CTFontGetSymbolicTraits(ctFont());
                            bool dsBold = (dsTraits & kCTFontTraitBold) || m_platformData.syntheticBold();
                            bool dsItalic = (dsTraits & kCTFontTraitItalic) || m_platformData.syntheticOblique();
                            styleCode = static_cast<uint16_t>((dsBold ? 1 : 0) | (dsItalic ? 2 : 0));
                        }
                        uint16_t advFontId = static_cast<uint16_t>(fontId + 100 * styleCode);
                        bool isAscii = (cp <= 0x7E);
                        // Tier 1: constexpr table (fast path, in CPU cache) — regular weight only.
                        if (isAscii && styleCode == 0) {
                            for (const auto& e : kDriftstackAsciiAdvanceTable) {
                                if (e.fontId > fontId)
                                    break;
                                if (e.fontId == fontId && e.sizePx == sizePx && e.codepoint == static_cast<uint32_t>(cp)) {
                                    if (s_dsFontVerbose)
                                        WTFLogAlways("[Driftstack-V121] HIT family='%s' resolved='%s' size=%u cp=U+%04X mac=%.4f → ios=%.4f",
                                            atlasKey, familyName.utf8().data(), sizePx, static_cast<uint32_t>(cp), advance.width, e.widthPx);
                                    return e.widthPx;
                                }
                            }
                        } else if (styleCode == 0) {
                            for (const auto& e : kDriftstackNonAsciiAdvanceTable) {
                                if (e.fontId > fontId)
                                    break;
                                if (e.fontId == fontId && e.sizePx == sizePx && e.codepoint == static_cast<uint32_t>(cp)) {
                                    static unsigned hits = 0;
                                    if (++hits <= 16)
                                        WTFLogAlways("[Driftstack-V688] HIT family='%s' resolved='%s' size=%u cp=U+%04X mac=%.4f → ios=%.4f",
                                            atlasKey, familyName.utf8().data(), sizePx, static_cast<uint32_t>(cp), advance.width, e.widthPx);
                                    return e.widthPx;
                                }
                            }
                        }
                        // V-690 Tier 2: DriftstackAdvanceAtlas binary file lookup (2.7M entries via mmap + binary search).
                        // Reached when constexpr tables miss. Covers the full V-405 fuzzer codepoint range.
                        const auto& atlas = DriftstackAdvanceAtlas::singleton();
                        if (atlas.isAvailable()) {
                            float w = atlas.lookup(advFontId, sizePx, static_cast<uint32_t>(cp));
                            if (w >= 0.0f) {
                                static unsigned hits = 0;
                                if (++hits <= 16)
                                    WTFLogAlways("[Driftstack-V690] HIT family='%s' fontId=%u size=%u cp=U+%04X mac=%.4f → ios=%.4f",
                                        atlasKey, fontId, sizePx, static_cast<uint32_t>(cp), advance.width, w);
                                return w;
                            }
                        }
                    }
                }
            }
        }
    }
#endif
    return advance.width;
}

#if PLATFORM(DRIFTSTACK)
// V-090 / Phase F.1.B-1: glyph→codepoint reverse map for the
// DriftstackEmojiAtlas. Built lazily on first access. Iterates the
// atlas's known codepoints, queries CTFont for the glyph each
// resolves to, stores reverse mapping. Cost: ~1426 CTFontGetGlyphsForCharacters
// calls per color-emoji font; one-time at first lookup.
char32_t Font::driftstackCodepointForColorGlyph(Glyph glyph) const
{
    if (!m_driftstackEmojiReverseMapBuilt) {
        const auto& atlas = DriftstackEmojiAtlas::singleton();
        if (!atlas.isAvailable()) {
            m_driftstackEmojiReverseMapBuilt = true;
            return 0;
        }

        RetainPtr<CTFontRef> font = ctFont();
        const auto& codepoints = atlas.codepoints();
        for (uint32_t cp : codepoints) {
            std::array<UniChar, 2> codeUnits {};
            std::array<CGGlyph, 2> glyphs {};
            CFIndex len;
            if (cp > 0xFFFFu) {
                uint32_t scalar = cp - 0x10000u;
                codeUnits[0] = 0xD800u | (scalar >> 10);
                codeUnits[1] = 0xDC00u | (scalar & 0x3FFu);
                len = 2;
            } else {
                codeUnits[0] = static_cast<UniChar>(cp);
                len = 1;
            }
            if (CTFontGetGlyphsForCharacters(font.get(), codeUnits.data(), glyphs.data(), len)) {
                if (glyphs[0])
                    m_driftstackEmojiReverseMap.set(glyphs[0], static_cast<char32_t>(cp));
            }
        }
        // DRIFTSTACK #42 (W2558): © ® ™ resolve to Apple Color Emoji COLOR glyphs under an emoji-first
        // canvas stack (verified colorGlyphType==Color), and the per-glyph COLOR atlas (DSPGCA1) HAS
        // their gray iPhone pixels — but DriftstackEmojiAtlas::codepoints() (this reverse-map source)
        // OMITS them, so a color-resolved © ® ™ glyph couldn't recover its codepoint → the color-atlas
        // lookup was skipped → CT rendered the Mac's BLANK Apple-Color-Emoji © → blank (ink=0). Map them
        // explicitly so the color dispatch recovers 0xA9/0xAE/0x2122 → serves the gray atlas (matching
        // the real iPhone). The colorGlyphType==Color gate keeps this canvas/emoji-first only; plain
        // text fonts render © as text (no color glyph), so body text is unaffected.
        for (uint32_t legacyCp : { 0x00A9u, 0x00AEu, 0x2122u }) {
            UniChar cu = static_cast<UniChar>(legacyCp);
            CGGlyph lg = 0;
            if (CTFontGetGlyphsForCharacters(font.get(), &cu, &lg, 1) && lg)
                m_driftstackEmojiReverseMap.set(lg, static_cast<char32_t>(legacyCp));
        }
        m_driftstackEmojiReverseMapBuilt = true;
        WTFLogAlways("[Driftstack] Font::driftstackCodepointForColorGlyph: built reverse map for color-emoji font, %u entries", static_cast<unsigned>(m_driftstackEmojiReverseMap.size()));
    }

    auto it = m_driftstackEmojiReverseMap.find(glyph);
    return it != m_driftstackEmojiReverseMap.end() ? it->value : 0;
}

// V-583.K-text Phase 3b: glyph→codepoint reverse map for DriftstackTextGlyphAtlas.
// Built lazily on first call. Iterates atlas's complete codepoint enumeration
// (all V-405 codepoints covered: ASCII + CJK + Arabic + Devanagari + Emoji),
// queries CTFont for each codepoint's glyph, stores reverse mapping.
// Cost: ~14000 CTFontGetGlyphsForCharacters calls per font; one-time at first
// text-render with atlas-available.
char32_t Font::driftstackCodepointForTextGlyph(Glyph glyph) const
{
    if (!m_driftstackTextGlyphReverseMapBuilt) {
        const auto& atlas = DriftstackTextGlyphAtlas::singleton();
        if (!atlas.isAvailable()) {
            m_driftstackTextGlyphReverseMapBuilt = true;
            return 0;
        }

        RetainPtr<CTFontRef> font = ctFont();
        auto codepoints = atlas.allCodepoints();
        for (uint32_t cp : codepoints) {
            std::array<UniChar, 2> codeUnits {};
            std::array<CGGlyph, 2> glyphs {};
            CFIndex len;
            if (cp > 0xFFFFu) {
                uint32_t scalar = cp - 0x10000u;
                codeUnits[0] = 0xD800u | (scalar >> 10);
                codeUnits[1] = 0xDC00u | (scalar & 0x3FFu);
                len = 2;
            } else {
                codeUnits[0] = static_cast<UniChar>(cp);
                len = 1;
            }
            if (CTFontGetGlyphsForCharacters(font.get(), codeUnits.data(), glyphs.data(), len)) {
                if (glyphs[0])
                    m_driftstackTextGlyphReverseMap.set(glyphs[0], static_cast<char32_t>(cp));
            }
        }
        m_driftstackTextGlyphReverseMapBuilt = true;
        WTFLogAlways("[Driftstack-V583K-text] reverse map built for family='%s', %u entries (atlas cps=%zu)",
            m_platformData.familyName().utf8().data(),
            static_cast<unsigned>(m_driftstackTextGlyphReverseMap.size()),
            codepoints.size());
    }

    auto it = m_driftstackTextGlyphReverseMap.find(glyph);
    return it != m_driftstackTextGlyphReverseMap.end() ? it->value : 0;
}

// V-090 / Phase F.1.B-2: decode atlas PNG bytes into a CGImageRef and
// cache per (codepoint, strikePPEM). Cache key encodes both as
// (codepoint << 32) | strikePPEM. The provider holds a CFData wrapper
// around the mmap'd atlas region; both the data and provider are
// process-lifetime stable since the atlas singleton is NeverDestroyed.
// V-148-Complex: per-pair iphone-vs-mac kerning delta. Public Font method
// callable from ComplexTextController (which doesn't go through
// Font::applyTransforms where V-138 v4 fires). Inlines the helper logic
// since the anonymous-namespace helpers have internal linkage.
float Font::driftstackPairKerningDelta(uint8_t leftCp, uint8_t rightCp, float macShapedAdvanceL) const
{
    using namespace DriftstackKerning;
    if (leftCp < 0x20 || leftCp > 0x7E || rightCp < 0x20 || rightCp > 0x7E)
        return 0.0f;
    // Inline resolveKerningFontId.
    const String& familyName = m_platformData.familyName();
    auto utf8 = familyName.utf8();
    auto utf8sv = std::string_view(utf8.data(), utf8.length());
    uint16_t fontId = 0xFFFF;
    for (size_t i = 0; i < kKerningFonts.size(); ++i) {
        if (utf8sv == kKerningFonts[i]) { fontId = static_cast<uint16_t>(i); break; }
    }
    if (fontId == 0xFFFF) {
        if (familyName == ".AppleSystemUIFont"_s || familyName == ".SF NS"_s) {
            for (size_t i = 0; i < kKerningFonts.size(); ++i)
                if (std::string_view(kKerningFonts[i]) == "-apple-system") { fontId = static_cast<uint16_t>(i); break; }
        } else if (familyName == "-webkit-sans-serif"_s || familyName == "Helvetica"_s) {
            for (size_t i = 0; i < kKerningFonts.size(); ++i)
                if (std::string_view(kKerningFonts[i]) == "sans-serif") { fontId = static_cast<uint16_t>(i); break; }
        } else if (familyName == "-webkit-serif"_s || familyName == "Times"_s) {
            for (size_t i = 0; i < kKerningFonts.size(); ++i)
                if (std::string_view(kKerningFonts[i]) == "serif") { fontId = static_cast<uint16_t>(i); break; }
        }
    }
    if (fontId == 0xFFFF)
        return 0.0f;
    const uint16_t sizePx = static_cast<uint16_t>(roundf(m_platformData.size()));
    // Inline findKerningCell binary search.
    const KerningCell* cell = nullptr;
    {
        size_t lo = 0, hi = kKerningCells.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            const auto& c = kKerningCells[mid];
            if (c.fontId < fontId || (c.fontId == fontId && c.sizePx < sizePx)) lo = mid + 1;
            else if (c.fontId > fontId || (c.fontId == fontId && c.sizePx > sizePx)) hi = mid;
            else { cell = &c; break; }
        }
    }
    if (!cell)
        return 0.0f;
    // Inline findKerningPair binary search.
    auto pairs = std::span<const KerningPair> { kKerningPairs }.subspan(cell->pairsOffset, cell->pairsCount);
    const KerningPair* p = nullptr;
    {
        size_t lo = 0, hi = pairs.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            const auto& kp = pairs[mid];
            if (kp.leftCp < leftCp || (kp.leftCp == leftCp && kp.rightCp < rightCp)) lo = mid + 1;
            else if (kp.leftCp > leftCp || (kp.leftCp == leftCp && kp.rightCp > rightCp)) hi = mid;
            else { p = &kp; break; }
        }
    }
    if (!p)
        return 0.0f;
    float iphoneKerning = static_cast<float>(p->kerningQ8) / 256.0f;
    // Inline naturalAdvanceForGlyph.
    UniChar ch = static_cast<UniChar>(leftCp);
    CGGlyph glyph = 0;
    CTFontRef ctf = ctFont();
    if (!ctf) return 0.0f;
    CTFontGetGlyphsForCharacters(ctf, &ch, &glyph, 1);
    if (!glyph) return 0.0f;
    CGSize adv = CGSizeZero;
    CTFontGetAdvancesForGlyphs(ctf, kCTFontOrientationHorizontal, &glyph, &adv, 1);
    float natural = static_cast<float>(adv.width);
    float macKerning = macShapedAdvanceL - natural;
    // V-149: snap Mac kerning to Q8 precision before delta — see comment
    // in applyDriftstackPairKerningOverride (Simple-path twin).
    float macKerningQ8Snapped = roundf(macKerning * 256.0f) / 256.0f;
    return iphoneKerning - macKerningQ8Snapped;
}

RetainPtr<CGImageRef> Font::driftstackAtlasImageForCodepoint(uint32_t codepoint, uint32_t strikePPEM, std::span<const uint8_t> pngBytes) const
{
    const uint64_t key = (static_cast<uint64_t>(codepoint) << 32) | strikePPEM;
    Locker locker(m_driftstackAtlasImageCacheLock);
    auto it = m_driftstackAtlasImageCache.find(key);
    if (it != m_driftstackAtlasImageCache.end())
        return it->value;
    RetainPtr<CFDataRef> data = adoptCF(CFDataCreate(kCFAllocatorDefault, pngBytes.data(), static_cast<CFIndex>(pngBytes.size())));
    if (!data)
        return { };
    RetainPtr<CGDataProviderRef> provider = adoptCF(CGDataProviderCreateWithCFData(data.get()));
    if (!provider)
        return { };
    RetainPtr<CGImageRef> image = adoptCF(CGImageCreateWithPNGDataProvider(provider.get(), nullptr, false, kCGRenderingIntentDefault));
    if (image)
        m_driftstackAtlasImageCache.add(key, image);
    return image;
}

RetainPtr<CGImageRef> Font::driftstackTextAtlasImageForCodepoint(uint32_t codepoint, uint32_t ptSize, std::span<const uint8_t> pngBytes) const
{
    const uint64_t key = (static_cast<uint64_t>(ptSize) << 32) | codepoint;
    Locker locker(m_driftstackTextAtlasImageCacheLock);
    auto it = m_driftstackTextAtlasImageCache.find(key);
    if (it != m_driftstackTextAtlasImageCache.end())
        return it->value;
    RetainPtr<CFDataRef> data = adoptCF(CFDataCreate(kCFAllocatorDefault, pngBytes.data(), static_cast<CFIndex>(pngBytes.size())));
    if (!data)
        return { };
    RetainPtr<CGDataProviderRef> provider = adoptCF(CGDataProviderCreateWithCFData(data.get()));
    if (!provider)
        return { };
    RetainPtr<CGImageRef> image = adoptCF(CGImageCreateWithPNGDataProvider(provider.get(), nullptr, false, kCGRenderingIntentDefault));
    if (image)
        m_driftstackTextAtlasImageCache.add(key, image);
    return image;
}
#endif

#if PLATFORM(DRIFTSTACK)
namespace {

using namespace DriftstackKerning;

static uint16_t resolveKerningFontId(const String& familyName)
{
    auto utf8 = familyName.utf8();
    auto utf8sv = std::string_view(utf8.data(), utf8.length());
    for (size_t i = 0; i < kKerningFonts.size(); ++i) {
        if (utf8sv == kKerningFonts[i])
            return static_cast<uint16_t>(i);
    }
    // V-138 fallback: Mac CT resolves CSS keywords to internal names.
    // Map them back to the analyzer's CSS-keyword ids.
    if (familyName == ".AppleSystemUIFont"_s || familyName == ".SF NS"_s) {
        for (size_t i = 0; i < kKerningFonts.size(); ++i)
            if (std::string_view(kKerningFonts[i]) == "-apple-system")
                return static_cast<uint16_t>(i);
    }
    if (familyName == "-webkit-sans-serif"_s || familyName == "Helvetica"_s) {
        for (size_t i = 0; i < kKerningFonts.size(); ++i)
            if (std::string_view(kKerningFonts[i]) == "sans-serif")
                return static_cast<uint16_t>(i);
    }
    if (familyName == "-webkit-serif"_s || familyName == "Times"_s) {
        for (size_t i = 0; i < kKerningFonts.size(); ++i)
            if (std::string_view(kKerningFonts[i]) == "serif")
                return static_cast<uint16_t>(i);
    }
    return 0xFFFF;
}

static const KerningCell* findKerningCell(uint16_t fontId, uint16_t sizePx)
{
    size_t lo = 0, hi = kKerningCells.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        const auto& c = kKerningCells[mid];
        if (c.fontId < fontId || (c.fontId == fontId && c.sizePx < sizePx))
            lo = mid + 1;
        else if (c.fontId > fontId || (c.fontId == fontId && c.sizePx > sizePx))
            hi = mid;
        else
            return &c;
    }
    return nullptr;
}

static const KerningPair* findKerningPair(std::span<const KerningPair> pairs, uint8_t left, uint8_t right)
{
    size_t lo = 0, hi = pairs.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        const auto& p = pairs[mid];
        if (p.leftCp < left || (p.leftCp == left && p.rightCp < right))
            lo = mid + 1;
        else if (p.leftCp > left || (p.leftCp == left && p.rightCp > right))
            hi = mid;
        else
            return &p;
    }
    return nullptr;
}

struct MacKerningCache {
    std::unordered_map<uint64_t, float> values;
    std::unordered_set<uint64_t> populatedCells;
    Lock mutex;
};

static MacKerningCache& macKerningCache()
{
    static NeverDestroyed<MacKerningCache> cache;
    return cache.get();
}

// V-138 v4: get the natural (un-kerned) advance for a single glyph via
// CTFontGetAdvancesForGlyphs. The CALLER computes mac kerning at the
// dispatch site as: (current shaped advance from glyphBuffer) - (this).
// Avoids the V-138 v1-v3 bug where CTFontShapeGlyphs(2-glyph, …) returns
// zero advances.
static float naturalAdvanceForGlyph(CTFontRef ctFont, uint8_t left)
{
    UniChar ch = static_cast<UniChar>(left);
    CGGlyph glyph = 0;
    CTFontGetGlyphsForCharacters(ctFont, &ch, &glyph, 1);
    if (!glyph)
        return 0.0f;
    CGSize adv = CGSizeZero;
    CTFontGetAdvancesForGlyphs(ctFont, kCTFontOrientationHorizontal, &glyph, &adv, 1);
    return static_cast<float>(adv.width);
}

// Legacy stub — kept so the cache + populate signature still compiles; the
// V-138 v4 path uses the per-glyph naturalAdvanceForGlyph + per-call shaped
// advance subtraction.
static float computeMacPairKerningOnce(CTFontRef, uint8_t, uint8_t)
{
    return 0.0f;
}

static void populateMacKerningCellOnce(uint16_t fontId, uint16_t sizePx,
    CTFontRef ctFont, std::span<const KerningPair> iPhonePairs)
{
    auto& cache = macKerningCache();
    Locker locker { cache.mutex };
    uint64_t cellKey = (static_cast<uint64_t>(fontId) << 16) | sizePx;
    if (cache.populatedCells.contains(cellKey))
        return;
    for (const auto& p : iPhonePairs) {
        uint64_t key = (cellKey << 16) | (static_cast<uint64_t>(p.leftCp) << 8) | p.rightCp;
        cache.values[key] = computeMacPairKerningOnce(ctFont, p.leftCp, p.rightCp);
    }
    cache.populatedCells.insert(cellKey);
}

static float lookupMacPairKerning(uint16_t fontId, uint16_t sizePx, uint8_t left, uint8_t right)
{
    auto& cache = macKerningCache();
    Locker locker { cache.mutex };
    uint64_t cellKey = (static_cast<uint64_t>(fontId) << 16) | sizePx;
    uint64_t key = (cellKey << 16) | (static_cast<uint64_t>(left) << 8) | right;
    auto it = cache.values.find(key);
    return it == cache.values.end() ? 0.0f : it->second;
}

static char32_t recoverCodepointFromGlyph(const GlyphBuffer& gb, unsigned glyphIdx,
    StringView source, unsigned beginningStringIndex)
{
    unsigned offset = static_cast<unsigned>(gb.uncheckedStringOffsetAt(glyphIdx)) + beginningStringIndex;
    if (offset >= source.length())
        return 0;
    if (source.is8Bit())
        return static_cast<char32_t>(source[offset]);
    UChar ch = source[offset];
    if (ch >= 0xD800 && ch <= 0xDBFF && offset + 1 < source.length()) {
        UChar low = source[offset + 1];
        if (low >= 0xDC00 && low <= 0xDFFF)
            return static_cast<char32_t>(0x10000 + ((ch - 0xD800) << 10) + (low - 0xDC00));
    }
    return static_cast<char32_t>(ch);
}

static void applyDriftstackPairKerningOverride(GlyphBuffer& glyphBuffer,
    unsigned beginningGlyphIndex, unsigned beginningStringIndex,
    bool enableKerning, CTFontRef ctFont, const String& familyName,
    float ptSize, StringView text)
{
    if (!enableKerning)
        return;
    if (glyphBuffer.size() <= beginningGlyphIndex + 1)
        return;
    uint16_t fontId = resolveKerningFontId(familyName);
    if (fontId == 0xFFFF)
        return;
    uint16_t sizePx = static_cast<uint16_t>(roundf(ptSize));
    const KerningCell* cell = findKerningCell(fontId, sizePx);
    if (!cell)
        return;
    auto pairs = std::span<const KerningPair> { kKerningPairs }.subspan(cell->pairsOffset, cell->pairsCount);

    // V-138 v4: at each glyph, natural advance (no kerning) is queried
    // via CTFontGetAdvancesForGlyphs. Mac kerning = shaped_advance -
    // natural. Then delta = iphone_kerning - mac_kerning. This bypasses
    // the v1-v3 CTFontShapeGlyphs-returns-zero bug.
    //
    // V-149 closure: Mac CTFontShapeGlyphs returns shaped advances at
    // sub-Q8 precision (e.g., -87.5/256 px between two Q8 steps). iPhone
    // CT's measureText effectively snaps kerning to Q8 boundaries
    // (consistent with the captured Q8.8 storage). Computing delta against
    // raw Mac shaped subtracts a sub-Q8 noise component that iPhone does
    // NOT actually apply, leaking 1 ULP / pair into the cumulative rig
    // (V-148-PM diagnostic confirmed -apple-system 0.002 px residual was
    // exactly this). Round Mac's measured kerning to Q8 first; only fire
    // when iPhone disagrees on the Q8-snapped value. Pixel rendering snap
    // is 1/16 px or coarser, so 1/256-precision suppression cannot change
    // canvas-fp pixel results.
    for (unsigned i = beginningGlyphIndex; i + 1 < glyphBuffer.size(); ++i) {
        char32_t leftCp = recoverCodepointFromGlyph(glyphBuffer, i, text, beginningStringIndex);
        char32_t rightCp = recoverCodepointFromGlyph(glyphBuffer, i + 1, text, beginningStringIndex);
        if (leftCp < 0x20 || leftCp > 0x7E || rightCp < 0x20 || rightCp > 0x7E)
            continue;
        const KerningPair* p = findKerningPair(pairs,
            static_cast<uint8_t>(leftCp), static_cast<uint8_t>(rightCp));
        if (!p)
            continue;
        float iphoneKerning = static_cast<float>(p->kerningQ8) / 256.0f;
        float natural = naturalAdvanceForGlyph(ctFont, static_cast<uint8_t>(leftCp));
        float shaped = WebCore::width(glyphBuffer.advanceAt(i));
        float macKerning = shaped - natural;
        float macKerningQ8Snapped = roundf(macKerning * 256.0f) / 256.0f;
        float delta = iphoneKerning - macKerningQ8Snapped;
        if (delta == 0.0f)
            continue;
        glyphBuffer.expandAdvance(i, delta);
    }
    (void)populateMacKerningCellOnce; (void)lookupMacPairKerning; // unused in v4
}

// W3061 (#79): U+2049 (⁉) SHAPED-advance ULP correction — the DEFINITIVE site. WidthIterator gets
// widthForGlyph=166.8 (design) but CTFontShapeGlyphs (this applyTransforms) OVERWRITES glyphBuffer's
// advance with CoreText's hinted SHAPED advance (166.81251525878906/0x4326d001 macOS @200px), and THAT
// is what getClientRects reads (proven: W3058 diag showed platformWidthForGlyph returns 166.8 but layout
// uses 166.8125 — the shaped advance). A real iPhone's shaped advance is 166.8125/0x4326d000, exactly 1
// float32 ULP below → +2^-16 on the CreepJS domrect width = the sole net driver of domrectSystemSum.
// platformWidthForGlyph (W3056) + ComplexTextController (W3057) were the WRONG paths (this glyph is SIMPLE
// codePath; the width is the SHAPED advance here). Serve the captured iPhone shaped advance per size (same
// 9 round-trip-verified values: f32(raw*1.000999)==captured getClientRects width). Value-self-scoped
// (shaped within 0.05px of the cell → CJK U+2049 in another face untouched) + codepoint match via the
// same recoverCodepointFromGlyph idiom as the kerning override. Runs UNCONDITIONALLY (advance correction,
// not kerning — not gated on enableKerning).
static void applyDriftstackU2049AdvanceOverride(GlyphBuffer& glyphBuffer, unsigned beginningGlyphIndex,
    unsigned beginningStringIndex, float ptSize, StringView text)
{
    // W3062 fire-diagnostic (TEMPORARY, remove after A3 reports): W3061 didn't move getClientRects. Is this
    // helper even reached? does recoverCodepointFromGlyph return 0x2049? what shaped advance does it see? does
    // expandAdvance run? Gated to the 200px probe (ptSize>150) to avoid flood.
    bool dsDiag = ptSize > 150.f;
    if (dsDiag)
        WTFLogAlways("[DS-U2049] CALLED ptSize=%.3f gbSize=%u begin=%u", ptSize, glyphBuffer.size(), beginningGlyphIndex);
    if (glyphBuffer.size() <= beginningGlyphIndex)
        return;
    static constexpr struct { int size; float adv; } k2049Advances[] = {
        {  50,  41.703125f          }, {  72,  60.0625f            },
        {  96,  80.07813262939453f  }, { 100,  83.40625f           },
        { 150, 125.109375f          }, { 200, 166.8125f            },
        { 300, 250.20314025878906f  }, { 400, 333.609375f          },
        { 600, 500.4062805175781f   },
    };
    int sizePx = static_cast<int>(roundf(ptSize));
    float target = -1.f;
    for (auto& c : k2049Advances) {
        if (c.size == sizePx) { target = c.adv; break; }
    }
    if (dsDiag)
        WTFLogAlways("[DS-U2049] sizePx=%d target=%.6f", sizePx, target);
    if (target < 0.f)
        return;
    for (unsigned i = beginningGlyphIndex; i < glyphBuffer.size(); ++i) {
        char32_t cp = recoverCodepointFromGlyph(glyphBuffer, i, text, beginningStringIndex);
        float shaped = WebCore::width(glyphBuffer.advanceAt(i));
        if (dsDiag && (cp == 0x2049 || (shaped > 160.f && shaped < 172.f)))
            WTFLogAlways("[DS-U2049] i=%u cp=U+%04X shaped=%.11f match=%d guard=%d", i, (unsigned)cp, shaped, (int)(cp == 0x2049), (int)(std::fabs(shaped - target) < 0.05f));
        if (cp != 0x2049)
            continue;
        if (std::fabs(shaped - target) < 0.05f) {
            glyphBuffer.expandAdvance(i, target - shaped);
            if (dsDiag)
                WTFLogAlways("[DS-U2049] FIRED i=%u new=%.11f", i, WebCore::width(glyphBuffer.advanceAt(i)));
        }
    }
}

} // anonymous namespace
#endif // PLATFORM(DRIFTSTACK)

GlyphBufferAdvance Font::applyTransforms(GlyphBuffer& glyphBuffer, unsigned beginningGlyphIndex, unsigned beginningStringIndex, bool enableKerning, bool requiresShaping, const AtomString& locale, StringView text, TextDirection textDirection) const
{
    UNUSED_PARAM(requiresShaping);

    if (!platformData().size())
        return makeGlyphBufferAdvance();

    auto handler = ^(CFRange range, CGGlyph** newGlyphsPointer, CGSize** newAdvancesPointer, CGPoint** newOffsetsPointer, CFIndex** newIndicesPointer)
    {
        range.location = std::min(std::max(range.location, static_cast<CFIndex>(0)), static_cast<CFIndex>(glyphBuffer.size()));
        if (range.length < 0) {
            range.length = std::min(range.location, -range.length);
            range.location = range.location - range.length;
            glyphBuffer.remove(beginningGlyphIndex + range.location, range.length);
            LOG_WITH_STREAM(TextShaping, stream << "Callback called to remove at location " << range.location << " and length " << range.length);
        } else {
            glyphBuffer.makeHole(beginningGlyphIndex + range.location, range.length, this);
            LOG_WITH_STREAM(TextShaping, stream << "Callback called to insert hole at location " << range.location << " and length " << range.length);
        }

        *newGlyphsPointer = glyphBuffer.glyphs(beginningGlyphIndex).data();
        *newAdvancesPointer = glyphBuffer.advances(beginningGlyphIndex).data();
        *newOffsetsPointer = glyphBuffer.origins(beginningGlyphIndex).data();
        *newIndicesPointer = glyphBuffer.offsetsInString(beginningGlyphIndex).data();
    };

    auto substring = text.substring(beginningStringIndex);
    constexpr unsigned bufferSize = 256;
    auto upconvertedCharacters = substring.upconvertedCharacters<bufferSize>();
    auto localeString = locale.isNull() ? nullptr : LocaleCocoa::canonicalLanguageIdentifierFromString(locale);
    auto numberOfInputGlyphs = glyphBuffer.size() - beginningGlyphIndex;
    // FIXME: Enable kerning for single glyphs when rdar://82195405 is fixed
    CTFontShapeOptions options = kCTFontShapeWithClusterComposition
        | (enableKerning && numberOfInputGlyphs ? kCTFontShapeWithKerning : 0)
        | (textDirection == TextDirection::RTL ? kCTFontShapeRightToLeft : 0);

    // FIXME: This shouldn't actually be necessary, if we pass in a pointer to the base of the string.
    for (unsigned i = 0; i < glyphBuffer.size() - beginningGlyphIndex; ++i)
        glyphBuffer.offsetsInString(beginningGlyphIndex)[i] -= beginningStringIndex;

    RetainPtr ctFont = this->ctFont();
    LOG_WITH_STREAM(TextShaping,
        stream << "Simple shaping " << numberOfInputGlyphs << " glyphs in font " << String(adoptCF(CTFontCopyPostScriptName(ctFont.get())).get()) << ".\n";
        stream << "Font attributes: " << String(adoptCF(CFCopyDescription(adoptCF(CTFontDescriptorCopyAttributes(adoptCF(CTFontCopyFontDescriptor(ctFont.get())).get())).get())).get()) << "\n";
        stream << "Locale: " << String(localeString.get()) << "\n";
        stream << "Options: " << options << "\n";
        auto glyphs = glyphBuffer.glyphs(beginningGlyphIndex);
        stream << "Glyphs:";
        for (auto& glyph : glyphs)
            stream << " " << glyph;
        stream << "\n";
        auto advances = glyphBuffer.advances(beginningGlyphIndex);
        stream << "Advances:";
        for (auto& advance : advances)
            stream << " " << FloatSize(advance);
        stream << "\n";
        auto origins = glyphBuffer.origins(beginningGlyphIndex);
        stream << "Origins:";
        for (auto& origin : origins)
            stream << " " << FloatPoint(origin);
        stream << "\n";
        auto offsets = glyphBuffer.offsetsInString(beginningGlyphIndex);
        stream << "Offsets:";
        for (auto& offset : offsets)
            stream << " " << offset;
        stream << "\n";
        auto codeUnits = upconvertedCharacters.span();
        stream << "Code Units:";
        for (unsigned i = 0; i < numberOfInputGlyphs; ++i)
            stream << " U+" << hex(codeUnits[i], 4);
    );

    auto initialAdvance = CTFontShapeGlyphs(
        ctFont.get(),
        glyphBuffer.glyphs(beginningGlyphIndex).data(),
        glyphBuffer.advances(beginningGlyphIndex).data(),
        glyphBuffer.origins(beginningGlyphIndex).data(),
        glyphBuffer.offsetsInString(beginningGlyphIndex).data(),
        reinterpret_cast<const UniChar*>(upconvertedCharacters.get()),
        numberOfInputGlyphs,
        options,
        localeString.get(),
        handler);

    LOG_WITH_STREAM(TextShaping,
        stream << "Shaping result: " << glyphBuffer.size() - beginningGlyphIndex << " glyphs.\n";
        auto glyphs = glyphBuffer.glyphs(beginningGlyphIndex);
        stream << "Glyphs:";
        for (auto& glyph : glyphs)
            stream << " " << glyph;
        stream << "\n";
        auto advances = glyphBuffer.advances(beginningGlyphIndex);
        stream << "Advances:";
        for (auto& advance : advances)
            stream << " " << FloatSize(advance);
        stream << "\n";
        auto origins = glyphBuffer.origins(beginningGlyphIndex);
        stream << "Origins:";
        for (auto& origin : origins)
            stream << " " << FloatPoint(origin);
        stream << "\n";
        auto offsets = glyphBuffer.offsetsInString(beginningGlyphIndex);
        stream << "Offsets:";
        for (auto& offset : offsets)
            stream << " " << offset;
        stream << "\n";
        stream << "Initial advance: " << FloatSize(initialAdvance);
    );

    ASSERT(numberOfInputGlyphs || glyphBuffer.size() == beginningGlyphIndex);
    ASSERT(numberOfInputGlyphs || (!initialAdvance.width && !initialAdvance.height));

#if PLATFORM(DRIFTSTACK)
    // V-126 closure: Mac CT and iOS CT apply different per-pair kerning.
    // After CTFontShapeGlyphs has applied Mac kerning, replace those
    // contributions with iPhone-equivalent kerning (delta-adjustment).
    // See /docs/architecture/v126-kerning-override-design.md.
    applyDriftstackPairKerningOverride(glyphBuffer, beginningGlyphIndex,
        beginningStringIndex, enableKerning, ctFont.get(),
        m_platformData.familyName(), m_platformData.size(), text);
    // W3061 (#79): correct U+2049's shaped advance to the iPhone value (unconditional — not kerning).
    applyDriftstackU2049AdvanceOverride(glyphBuffer, beginningGlyphIndex,
        beginningStringIndex, m_platformData.size(), text);
#endif

    for (unsigned i = 0; i < glyphBuffer.size() - beginningGlyphIndex; ++i)
        glyphBuffer.offsetsInString(beginningGlyphIndex)[i] += beginningStringIndex;

    if (textDirection == TextDirection::RTL)
        glyphBuffer.reverse(beginningGlyphIndex, glyphBuffer.size() - beginningGlyphIndex);

    return initialAdvance;
}

static int extractNumber(CFNumberRef number)
{
    int result = 0;
    if (number)
        CFNumberGetValue(number, kCFNumberIntType, &result);
    return result;
}

static bool extractBoolean(CFBooleanRef value)
{
    if (value)
        return CFBooleanGetValue(value);
    return false;
}

void Font::determinePitch()
{
    RetainPtr ctFont = this->ctFont();
    ASSERT(ctFont);

    // Special case Osaka-Mono.
    // According to <rdar://problem/3999467>, we should treat Osaka-Mono as fixed pitch.
    // Note that the AppKit does not report Osaka-Mono as fixed pitch.

    // Special case MS-PGothic.
    // According to <rdar://problem/4032938>, we should not treat MS-PGothic as fixed pitch.
    // Note that AppKit does report MS-PGothic as fixed pitch.

    // Special case MonotypeCorsiva
    // According to <rdar://problem/5454704>, we should not treat MonotypeCorsiva as fixed pitch.
    // Note that AppKit does report MonotypeCorsiva as fixed pitch.

    auto fullName = adoptCF(CTFontCopyFullName(ctFont.get()));
    auto familyName = adoptCF(CTFontCopyFamilyName(ctFont.get()));

    int fixedPitch = extractNumber(adoptCF(static_cast<CFNumberRef>(CTFontCopyAttribute(ctFont.get(), kCTFontFixedAdvanceAttribute))).get());
    bool userInstalled = extractBoolean(adoptCF(static_cast<CFBooleanRef>(CTFontCopyAttribute(ctFont.get(), kCTFontUserInstalledAttribute))).get());
    m_treatAsFixedPitch = (CTFontGetSymbolicTraits(ctFont.get()) & kCTFontMonoSpaceTrait) || fixedPitch || (caseInsensitiveCompare(fullName.get(), CFSTR("Osaka-Mono")) || caseInsensitiveCompare(fullName.get(), CFSTR("MS-PGothic")) || caseInsensitiveCompare(fullName.get(), CFSTR("MonotypeCorsiva")));
    if (familyName && caseInsensitiveCompare(familyName.get(), CFSTR("Courier New"))) {
#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
        // Special case Courier New to not be treated as fixed pitch, as this will make use of a hacked space width which is undesireable for iPhone (see rdar://6269783).
        m_treatAsFixedPitch = false;
#endif
        // "Courier New" has many special case characters which does not have widths (u0181, u0182 etc.). Thus we disable fast content measuring for monospace fonts.
        m_canTakeFixedPitchFastContentMeasuring = false;
    } else
        m_canTakeFixedPitchFastContentMeasuring = m_treatAsFixedPitch && !userInstalled;
}

#if PLATFORM(DRIFTSTACK)
// V-080 / V-081 Stage D-2 Track 2: iPhone normalizes ALL color-emoji glyph
// bboxes to a per-size canonical value, INDEPENDENT of glyph codepoint AND
// of the rendering font. Captured empirically (Stage D-3 emoji matrix,
// 2026-05-01: 15 distinct emoji × 89 sizes × 2 fonts → identical
// (width, ABA, ABD) per size). Mac CoreText returns smaller per-glyph
// bboxes from the same iOS font binary; clamp to iPhone canonical
// values whenever the queried glyph is a color glyph.
//
// Table: per-size (width, ascent, descent) tuples for sizes [8..96].
// Ascent / descent are FloatRect-coordinate values (positive ascent
// becomes -y in the WebKit-local convention; positive descent becomes
// +maxY). Width is the glyph's advance-width-equivalent bbox horizontal
// extent.
struct DriftstackEmojiBboxEntry { float size; float width; float ascent; float descent; };
// All values are exact 1/64-px multiples (LayoutUnit precision).
// Formatted as decimal-representable-as-float fractions to avoid
// rounding noise (the iPhone-canonical 13.640625 = 873/64).
static constexpr std::array<DriftstackEmojiBboxEntry, 89> driftstackEmojiBboxTable = {{
    {   8.f,  11.f,        7.796875f,    2.1875f },     {   9.f,  12.f,        8.765625f,    2.46875f },
    {  10.f,  13.f,        9.75f,        2.75f },       {  11.f,  15.f,       10.71875f,     3.015625f },
    {  12.f,  16.f,       11.6875f,      3.296875f },   {  13.f,  17.f,       12.671875f,    3.5625f },
    {  14.f,  19.f,       13.640625f,    3.84375f },    {  15.f,  20.f,       14.625f,       4.125f },
    {  16.f,  21.f,       15.59375f,     4.390625f },   {  17.f,  22.f,       16.1875f,      4.296875f },
    {  18.f,  22.f,       16.796875f,    4.1875f },     {  19.f,  23.f,       17.390625f,    4.09375f },
    {  20.f,  23.f,       18.f,          4.f },         {  21.f,  23.f,       18.59375f,     3.890625f },
    {  22.f,  24.f,       19.1875f,      3.796875f },   {  23.f,  24.f,       19.796875f,    3.6875f },
    {  24.f,  25.f,       20.390625f,    3.59375f },    {  25.f,  26.f,       21.25f,        3.75f },
    {  26.f,  26.f,       22.09375f,     3.890625f },   {  27.f,  27.f,       22.9375f,      4.046875f },
    {  28.f,  28.f,       23.796875f,    4.1875f },     {  29.f,  29.f,       24.640625f,    4.34375f },
    {  30.f,  30.f,       25.5f,         4.5f },        {  31.f,  31.f,       26.34375f,     4.640625f },
    {  32.f,  32.f,       27.1875f,      4.796875f },   {  33.f,  33.f,       28.046875f,    4.9375f },
    {  34.f,  34.f,       28.890625f,    5.09375f },    {  35.f,  35.f,       29.75f,        5.25f },
    {  36.f,  36.f,       30.59375f,     5.390625f },   {  37.f,  37.f,       31.4375f,      5.546875f },
    {  38.f,  38.f,       32.296875f,    5.6875f },     {  39.f,  39.f,       33.140625f,    5.84375f },
    {  40.f,  40.f,       34.f,          6.f },         {  41.f,  41.f,       34.84375f,     6.140625f },
    {  42.f,  42.f,       35.6875f,      6.296875f },   {  43.f,  43.f,       36.546875f,    6.4375f },
    {  44.f,  44.f,       37.390625f,    6.59375f },    {  45.f,  45.f,       38.25f,        6.75f },
    {  46.f,  46.f,       39.09375f,     6.890625f },   {  47.f,  47.f,       39.9375f,      7.046875f },
    {  48.f,  48.f,       40.796875f,    7.1875f },     {  49.f,  49.f,       41.640625f,    7.34375f },
    {  50.f,  50.f,       42.5f,         7.5f },        {  51.f,  51.f,       43.34375f,     7.640625f },
    {  52.f,  52.f,       44.1875f,      7.796875f },   {  53.f,  53.f,       45.046875f,    7.9375f },
    {  54.f,  54.f,       45.890625f,    8.09375f },    {  55.f,  55.f,       46.75f,        8.25f },
    {  56.f,  56.f,       47.59375f,     8.390625f },   {  57.f,  57.f,       48.4375f,      8.546875f },
    {  58.f,  58.f,       49.296875f,    8.6875f },     {  59.f,  59.f,       50.140625f,    8.84375f },
    {  60.f,  60.f,       51.f,          9.f },         {  61.f,  61.f,       51.84375f,     9.140625f },
    {  62.f,  62.f,       52.6875f,      9.296875f },   {  63.f,  63.f,       53.546875f,    9.4375f },
    {  64.f,  64.f,       54.390625f,    9.59375f },    {  65.f,  65.f,       55.25f,        9.75f },
    {  66.f,  66.f,       56.09375f,     9.890625f },   {  67.f,  67.f,       56.9375f,     10.046875f },
    {  68.f,  68.f,       57.796875f,   10.1875f },     {  69.f,  69.f,       58.640625f,   10.34375f },
    {  70.f,  70.f,       59.5f,        10.5f },        {  71.f,  71.f,       60.34375f,    10.640625f },
    {  72.f,  72.f,       61.1875f,     10.796875f },   {  73.f,  73.f,       62.046875f,   10.9375f },
    {  74.f,  74.f,       62.890625f,   11.09375f },    {  75.f,  75.f,       63.75f,       11.25f },
    {  76.f,  76.f,       64.59375f,    11.390625f },   {  77.f,  77.f,       65.4375f,     11.546875f },
    {  78.f,  78.f,       66.296875f,   11.6875f },     {  79.f,  79.f,       67.140625f,   11.84375f },
    {  80.f,  80.f,       68.f,         12.f },         {  81.f,  81.f,       68.84375f,    12.140625f },
    {  82.f,  82.f,       69.6875f,     12.296875f },   {  83.f,  83.f,       70.546875f,   12.4375f },
    {  84.f,  84.f,       71.390625f,   12.59375f },    {  85.f,  85.f,       72.25f,       12.75f },
    {  86.f,  86.f,       73.09375f,    12.890625f },   {  87.f,  87.f,       73.9375f,     13.046875f },
    {  88.f,  88.f,       74.796875f,   13.1875f },     {  89.f,  89.f,       75.640625f,   13.34375f },
    {  90.f,  90.f,       76.5f,        13.5f },        {  91.f,  91.f,       77.34375f,    13.640625f },
    {  92.f,  92.f,       78.1875f,     13.796875f },   {  93.f,  93.f,       79.046875f,   13.9375f },
    {  94.f,  94.f,       79.890625f,   14.09375f },    {  95.f,  95.f,       80.75f,       14.25f },
    {  96.f,  96.f,       81.59375f,    14.390625f }
}};

// The original Stage D-3 table captured ascent/descent across the full integer
// range but its horizontal column predated the full-range raw TextMetrics
// capture. Safari 26.2/26.3/26.4 agree exactly: the last small strike tapers
// from +9/64 to +3/64 at 26..28px, then every 29..96px bbox is advance+0.5.
// Preserve the table's linear behavior for fractional point sizes.
static float driftstackEmojiBboxWidthForSize(float size, float tableWidth)
{
    if (size < 26.f)
        return tableWidth;
    if (size < 28.f)
        return size + 0.140625f - (size - 26.f) * 0.046875f;
    if (size < 29.f)
        return 28.046875f + (size - 28.f) * 1.453125f;
    if (size < 96.f)
        return size + 0.5f;
    return 96.5f;
}

// Linear-interp lookup. Sizes outside [8, 96] clamp to nearest endpoint.
// Most canvas sizes are integer points so the interp branch rarely fires.
static FloatRect driftstackEmojiBboxForSize(float size)
{
    if (size <= driftstackEmojiBboxTable.front().size) {
        const auto& e = driftstackEmojiBboxTable.front();
        return FloatRect(0, -e.ascent, driftstackEmojiBboxWidthForSize(size, e.width), e.ascent + e.descent);
    }
    if (size >= driftstackEmojiBboxTable.back().size) {
        const auto& e = driftstackEmojiBboxTable.back();
        return FloatRect(0, -e.ascent, driftstackEmojiBboxWidthForSize(size, e.width), e.ascent + e.descent);
    }
    DriftstackEmojiBboxEntry a = driftstackEmojiBboxTable.front();
    for (const auto& b : driftstackEmojiBboxTable) {
        if (size >= a.size && size <= b.size && a.size != b.size) {
            float t = (size - a.size) / (b.size - a.size);
            float w = a.width   + t * (b.width   - a.width);
            float ascent  = a.ascent  + t * (b.ascent  - a.ascent);
            float descent = a.descent + t * (b.descent - a.descent);
            return FloatRect(0, -ascent, driftstackEmojiBboxWidthForSize(size, w), ascent + descent);
        }
        a = b;
    }
    // Unreachable: above branches cover all cases.
    return FloatRect();
}
#endif

FloatRect Font::platformBoundsForGlyph(Glyph glyph) const
{
    FloatRect boundingBox;
    CGRect ignoredRect = { };
    boundingBox = CTFontGetBoundingRectsForGlyphs(protect(ctFont()).get(), platformData().orientation() == FontOrientation::Vertical ? kCTFontOrientationVertical : kCTFontOrientationHorizontal, &glyph, &ignoredRect, 1);
    boundingBox.setY(-boundingBox.maxY());
    boundingBox.setWidth(boundingBox.width() + m_syntheticBoldOffset);

#if PLATFORM(DRIFTSTACK)
    if (colorGlyphType(glyph) == ColorGlyphType::Color)
        return driftstackEmojiBboxForSize(m_platformData.size());

    // V-484 redesign empirical PROBE — diagnostic-only, no behavioural change.
    // Logs (font-family, glyph-id, point-size, bounds) for iOS Stage B
    // complex-script fonts at canonical probe sizes. Output feeds layer
    // identification for V-484 redesign (per-glyph clamp vs TextMetrics
    // substitution vs glyph-buffer construction). Gated by env var
    // DRIFTSTACK_V484_PROBE=1 to keep production builds noise-free; the
    // rig launcher /tmp/v481b-track7d-cumulative.sh sets this when active.
    {
        static const bool probeEnabled = []() {
            const char* v = std::getenv("DRIFTSTACK_V484_PROBE");
            return v && *v && *v != '0';
        }();
        if (probeEnabled) {
            auto familyRef = adoptCF(CTFontCopyFamilyName(protect(ctFont()).get()));
            if (familyRef) {
                auto family = String(familyRef.get());
                bool isTargetFamily =
                       family == "PingFang SC"_s || family == "PingFang HK"_s
                    || family == "PingFang TC"_s || family == "Hiragino Sans"_s
                    || family == "Hiragino Mincho ProN"_s || family == "Hiragino Mincho Pro"_s
                    || family == "Geeza Pro"_s || family == ".SF Hebrew"_s
                    || family == ".SF Hebrew Rounded"_s || family == "Times"_s
                    || family == "Times New Roman"_s || family == "serif"_s;
                if (isTargetFamily) {
                    static unsigned probeCount = 0;
                    if (++probeCount <= 200) {
                        WTFLogAlways("[Driftstack-V484-PROBE] family='%s' size=%.2f glyph=%u bounds={x=%.4f,y=%.4f,w=%.4f,h=%.4f}",
                            family.utf8().data(), m_platformData.size(), glyph,
                            boundingBox.x(), boundingBox.y(), boundingBox.width(), boundingBox.height());
                    }
                }
            }
        }
    }
#endif

    return boundingBox;
}

Vector<FloatRect, Font::inlineGlyphRunCapacity> Font::platformBoundsForGlyphs(const Vector<Glyph, inlineGlyphRunCapacity>& glyphs) const
{
    Vector<CGRect, inlineGlyphRunCapacity> rectsForGlyphs(glyphs.size());
    CTFontGetBoundingRectsForGlyphs(protect(ctFont()).get(), platformData().orientation() == FontOrientation::Vertical ? kCTFontOrientationVertical : kCTFontOrientationHorizontal, glyphs.span().data(), rectsForGlyphs.mutableSpan().data(), rectsForGlyphs.size());

#if PLATFORM(DRIFTSTACK)
    Vector<FloatRect, Font::inlineGlyphRunCapacity> result;
    result.reserveInitialCapacity(glyphs.size());
    const float fontSize = m_platformData.size();
    for (size_t i = 0; i < glyphs.size(); ++i) {
        if (colorGlyphType(glyphs[i]) == ColorGlyphType::Color) {
            result.append(driftstackEmojiBboxForSize(fontSize));
            continue;
        }
        FloatRect boundingBox(rectsForGlyphs[i]);
        boundingBox.setY(-boundingBox.maxY());
        boundingBox.setWidth(boundingBox.width() + m_syntheticBoldOffset);
        result.append(boundingBox);
    }
    return result;
#else
    return rectsForGlyphs.map<Vector<FloatRect, inlineGlyphRunCapacity>>([&](const auto& rect) -> auto {
        FloatRect boundingBox(rect);
        boundingBox.setY(-boundingBox.maxY());
        boundingBox.setWidth(boundingBox.width() + m_syntheticBoldOffset);
        return boundingBox;
    });
#endif
}

Path Font::platformPathForGlyph(Glyph glyph) const
{
    auto result = adoptCF(CTFontCreatePathForGlyph(protect(ctFont()).get(), glyph, nullptr));
    if (!result)
        return { };

    auto syntheticBoldOffset = this->syntheticBoldOffset();
    if (syntheticBoldOffset) {
        auto newPath = adoptCF(CGPathCreateMutable());
        CGPathAddPath(newPath.get(), nullptr, result.get());
        auto translation = CGAffineTransformMakeTranslation(syntheticBoldOffset, 0);
        CGPathAddPath(newPath.get(), &translation, result.get());
        return { PathCG::create(WTF::move(newPath)) };
    }

    return { PathCG::create(adoptCF(CGPathCreateMutableCopy(result.get()))) };
}

bool Font::platformSupportsCodePoint(char32_t character, std::optional<char32_t> variation) const
{
    if (variation)
        return false;

    std::array<UniChar, 2> codeUnits;
    std::array<CGGlyph, 2> glyphs;
    CFIndex count = 0;
    U16_APPEND_UNSAFE(codeUnits, count, character);
    return CTFontGetGlyphsForCharacters(protect(ctFont()).get(), codeUnits.data(), glyphs.data(), count);
}

static bool hasGlyphsForCharacterRange(CTFontRef font, UniChar firstCharacter, UniChar lastCharacter, bool expectValidGlyphsForAllCharacters)
{
    const unsigned numberOfCharacters = lastCharacter - firstCharacter + 1;
    Vector<CGGlyph> glyphs(FillWith { }, numberOfCharacters, 0);
    CTFontGetGlyphsForCharacterRange(font, glyphs.begin(), CFRangeMake(firstCharacter, numberOfCharacters));
    glyphs.removeAll(0);

    if (glyphs.isEmpty())
        return false;

    Vector<CGRect> boundingRects(FillWith { }, glyphs.size(), CGRectZero);
    CTFontGetBoundingRectsForGlyphs(font, kCTFontOrientationDefault, glyphs.begin(), boundingRects.begin(), glyphs.size());

    unsigned validGlyphsCount = 0;
    for (auto& rect : boundingRects) {
        if (!CGRectIsEmpty(rect))
            ++validGlyphsCount;
    }

    if (expectValidGlyphsForAllCharacters)
        return validGlyphsCount == glyphs.size();

    return validGlyphsCount;
}

bool Font::isProbablyOnlyUsedToRenderIcons() const
{
    RetainPtr platformFont = ctFont();
    if (!platformFont)
        return false;

    // Allow most non-icon fonts to bail early here by testing a single character 'a', without iterating over all basic latin characters.
    UniChar lowercaseACharacter = 'a';
    CGGlyph lowercaseAGlyph;
    if (CTFontGetGlyphsForCharacters(platformFont.get(), &lowercaseACharacter, &lowercaseAGlyph, 1)) {
        CGRect ignoredRect = { };
        if (!CGRectIsEmpty(CTFontGetBoundingRectsForGlyphs(platformFont.get(), kCTFontOrientationDefault, &lowercaseAGlyph, &ignoredRect, 1)))
            return false;
    }

    auto supportedCharacters = adoptCF(CTFontCopyCharacterSet(platformFont.get()));
    if (CFCharacterSetHasMemberInPlane(supportedCharacters.get(), 1) || CFCharacterSetHasMemberInPlane(supportedCharacters.get(), 2))
        return false;

    return !hasGlyphsForCharacterRange(platformFont.get(), ' ', '~', false) && !hasGlyphsForCharacterRange(platformFont.get(), 0x0600, 0x06FF, true);
}

const PAL::OTSVGTable& Font::otSVGTable() const
{
    if (!m_otSVGTable) {
        if (auto tableData = adoptCF(CTFontCopyTable(protect(ctFont()).get(), kCTFontTableSVG, kCTFontTableOptionNoOptions)))
            m_otSVGTable = PAL::OTSVGTable(tableData.get(), fontMetrics().unitsPerEm(), platformData().size());
        else
            m_otSVGTable = {{ }};
    }
    return m_otSVGTable.value();
}

Font::ComplexColorFormatGlyphs Font::ComplexColorFormatGlyphs::createWithNoRelevantTables()
{
    return { false, 0 };
}

Font::ComplexColorFormatGlyphs Font::ComplexColorFormatGlyphs::createWithRelevantTablesAndGlyphCount(unsigned glyphCount)
{
    return { true, glyphCount };
}

bool NODELETE Font::ComplexColorFormatGlyphs::hasValueFor(Glyph glyph) const
{
    return m_bits.contains(bitForInitialized(glyph));
}

bool NODELETE Font::ComplexColorFormatGlyphs::get(Glyph glyph) const
{
    ASSERT(hasValueFor(glyph));
    return m_bits.contains(bitForValue(glyph));
}

void Font::ComplexColorFormatGlyphs::set(Glyph glyph, bool value)
{
    ASSERT(m_hasRelevantTables);
    ASSERT(!hasValueFor(glyph));
    m_bits.set(bitForInitialized(glyph));
    if (value)
        m_bits.set(bitForValue(glyph));
}

bool Font::hasComplexColorFormatTables() const
{
    if (otSVGTable().table)
        return true;

#if HAVE(CORE_TEXT_SBIX_IMAGE_SIZE_FUNCTIONS)
    if (auto sbixTableData = adoptCF(CTFontCopyTable(protect(ctFont()).get(), kCTFontTableSbix, kCTFontTableOptionNoOptions)))
        return true;
#endif

    return false;
}

Font::ComplexColorFormatGlyphs& Font::glyphsWithComplexColorFormat() const
{
    if (!m_glyphsWithComplexColorFormat) {
        if (hasComplexColorFormatTables()) {
            CFIndex glyphCount = CTFontGetGlyphCount(protect(ctFont()).get());
            if (glyphCount >= 0) {
                m_glyphsWithComplexColorFormat = ComplexColorFormatGlyphs::createWithRelevantTablesAndGlyphCount(glyphCount);
                return m_glyphsWithComplexColorFormat.value();
            }
        }
        m_glyphsWithComplexColorFormat = ComplexColorFormatGlyphs::createWithNoRelevantTables();
    }
    return m_glyphsWithComplexColorFormat.value();
}

bool Font::glyphHasComplexColorFormat(Glyph glyphID) const
{
#if HAVE(CORE_TEXT_GLYPHHASCOMPLEXCOLOR_FUNCTION)
    if (PAL::canLoad_CoreText_CTFontHasComplexColorFormatForGlyph())
        return PAL::softLink_CoreText_CTFontHasComplexColorFormatForGlyph(protect(ctFont()).get(), glyphID);
#endif

    if (auto svgTable = otSVGTable().table) {
        if (PAL::softLinkOTSVGOTSVGTableGetDocumentIndexForGlyph(svgTable, glyphID) != kCFNotFound)
            return true;
    }

#if HAVE(CORE_TEXT_SBIX_IMAGE_SIZE_FUNCTIONS)
    // There's no function to directly look up the sbix table, so use the fact that this one returns a non-zero value iff there's an sbix entry.
    if (CTFontGetSbixImageSizeForGlyphAndContentsScale(protect(ctFont()).get(), glyphID, 0))
        return true;
#endif

    return false;
}

std::optional<BitVector> Font::findOTSVGGlyphs(std::span<const GlyphBufferGlyph> glyphs) const
{
    auto table = otSVGTable().table;
    if (!table)
        return { };

    std::optional<BitVector> result;
    for (size_t i = 0; i < glyphs.size(); ++i) {
        if (PAL::softLinkOTSVGOTSVGTableGetDocumentIndexForGlyph(table, glyphs[i]) != kCFNotFound) {
            if (!result)
                result = BitVector(glyphs.size());
            result.value().quickSet(i);
        }
    }
    return result;
}

bool Font::hasAnyComplexColorFormatGlyphs(std::span<const GlyphBufferGlyph> glyphs) const
{
    auto& complexGlyphs = glyphsWithComplexColorFormat();
    if (!complexGlyphs.hasRelevantTables())
        return false;

    for (auto glyph : glyphs) {
        if (!complexGlyphs.hasValueFor(glyph))
            complexGlyphs.set(glyph, glyphHasComplexColorFormat(glyph));

        if (complexGlyphs.get(glyph))
            return true;
    }
    return false;
}

std::optional<Ref<Font>> Font::fromIPCData(IPCFontData&& data)
{
    return WTF::switchOn(WTF::move(data),
        [] (InstalledFont&& installedFont) -> std::optional<Ref<Font>> {
            return installedFont.toFont();
        },
        [] (CustomFontCreationData&& creationData) -> std::optional<Ref<Font>> {
            Ref fontFaceData = SharedBuffer::create(WTF::move(creationData.fontFaceData));
            RefPtr<FontCustomPlatformData> customPlatformData = FontCustomPlatformData::create(fontFaceData, creationData.itemInCollection);
            if (!customPlatformData)
                return std::nullopt;

            RetainPtr baseFontDescriptor = customPlatformData->fontDescriptor.get();
            if (!baseFontDescriptor)
                return std::nullopt;

            RetainPtr<CFDictionaryRef> attributesDictionary = creationData.attributes ? creationData.attributes->toCFDictionary() : nullptr;
            RetainPtr fontDescriptor = adoptCF(CTFontDescriptorCreateCopyWithAttributes(baseFontDescriptor.get(), attributesDictionary.get()));

            RetainPtr font = adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor.get(), creationData.metadata.pointSize, nullptr));

            return Font::create(FontPlatformData(creationData.metadata.pointSize, FontOrientation(creationData.metadata.orientation), FontWidthVariant(creationData.metadata.widthVariant), TextRenderingMode(creationData.metadata.textRenderingMode), creationData.metadata.syntheticBold, creationData.metadata.syntheticOblique, WTF::move(font), WTF::move(customPlatformData)));
        }
    );
}

std::optional<InstalledFont> Font::toSerializableInstalledFont() const
{
    RetainPtr ctFont = this->ctFont();
    if (!ctFont || m_platformData.creationData())
        return std::nullopt;

    FontMetadata fontData = {
        CTFontGetSize(ctFont.get()),
        platformData().orientation(),
        platformData().widthVariant(),
        platformData().textRenderingMode(),
        platformData().syntheticBold(),
        platformData().syntheticOblique()
    };

    SystemUIFontType fontType = CTFontGetUIFontType(ctFont.get());
    if (fontType != SystemUIFontTypeNone) {
        return InstalledFont {
            InstalledFont::SystemUIFont {
                fontType,
                adoptCF(checked_cf_cast<CFStringRef>(CTFontCopyAttribute(ctFont.get(), kCTFontDescriptorLanguageAttribute))).get()
            },
            fontData
        };
    }

    RetainPtr fontDescriptor = adoptCF(CTFontCopyFontDescriptor(ctFont.get()));
    RetainPtr attributes = adoptCF(CTFontDescriptorCopyAttributes(fontDescriptor.get()));
    return InstalledFont {
        InstalledFont::PostScriptFont {
            String(adoptCF(CTFontCopyPostScriptName(ctFont.get())).get()),
            CTFontDescriptorGetOptions(fontDescriptor.get()),
            FontPlatformSerializedAttributes::fromCF(attributes.get())
        },
        fontData
    };
}

IPCFontData Font::toSerializableFont() const
{
    std::optional<InstalledFont> installedFont = toSerializableInstalledFont();
    if (installedFont)
        return { *installedFont };

    RetainPtr font = ctFont();
    RetainPtr fontDescriptor = adoptCF(CTFontCopyFontDescriptor(font.get()));
    RetainPtr attributes = adoptCF(CTFontDescriptorCopyAttributes(fontDescriptor.get()));

    const auto& data = m_platformData.creationData();
    FontMetadata fontData = {
        CTFontGetSize(font.get()),
        m_platformData.orientation(),
        m_platformData.widthVariant(),
        m_platformData.textRenderingMode(),
        m_platformData.syntheticBold(),
        m_platformData.syntheticOblique()
    };

    return { CustomFontCreationData { fontData, { data->fontFaceData->span() }, FontPlatformSerializedAttributes::fromCF(attributes.get()), data->itemInCollection } };
}

#if ENABLE(MULTI_REPRESENTATION_HEIC)

MultiRepresentationHEICMetrics Font::metricsForMultiRepresentationHEIC() const
{
    CGRect bounds = CTFontGetTypographicBoundsForAdaptiveImageProvider(ctFont(), nullptr);

    MultiRepresentationHEICMetrics metrics;
    metrics.ascent = CGRectGetMaxY(bounds);
    metrics.descent = -CGRectGetMinY(bounds);
    metrics.width = CGRectGetMaxX(bounds);
    return metrics;
}

#endif

} // namespace WebCore
