/*
 * Copyright (C) 2013 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import "config.h"
#import "PlatformSpeechSynthesizer.h"

#if ENABLE(SPEECH_SYNTHESIS) && PLATFORM(COCOA)

#import "PlatformSpeechSynthesisUtterance.h"
#import "PlatformSpeechSynthesisVoice.h"

#if __has_include(<AVFAudio/AVSpeechSynthesis.h>)
#import <AVFAudio/AVSpeechSynthesis.h>
#else
#import <AVFoundation/AVFoundation.h>
#endif

#import <pal/spi/cocoa/AXSpeechManagerSPI.h>
#import <wtf/BlockObjCExceptions.h>
#import <wtf/MainThread.h>
#import <wtf/RetainPtr.h>

#import <pal/cocoa/AVFoundationSoftLink.h>

static float getAVSpeechUtteranceDefaultSpeechRate()
{
    static float value;
    static void* symbol;
    if (!symbol) {
        void* symbol = dlsym(PAL::AVFoundationLibrary(), "AVSpeechUtteranceDefaultSpeechRate");
        RELEASE_ASSERT_WITH_MESSAGE(symbol, "%s", dlerror());
        value = *static_cast<float const *>(symbol);
    }
    return value;
}

static float getAVSpeechUtteranceMaximumSpeechRate()
{
    static float value;
    static void* symbol;
    if (!symbol) {
        void* symbol = dlsym(PAL::AVFoundationLibrary(), "AVSpeechUtteranceMaximumSpeechRate");
        RELEASE_ASSERT_WITH_MESSAGE(symbol, "%s", dlerror());
        value = *static_cast<float const *>(symbol);
    }
    return value;
}

#define AVSpeechUtteranceDefaultSpeechRate getAVSpeechUtteranceDefaultSpeechRate()
#define AVSpeechUtteranceMaximumSpeechRate getAVSpeechUtteranceMaximumSpeechRate()

@interface WebSpeechSynthesisWrapper : NSObject<AVSpeechSynthesizerDelegate> {
    WeakPtr<WebCore::PlatformSpeechSynthesizer> m_synthesizerObject;
    // Hold a Ref to the utterance so that it won't disappear until the synth is done with it.
    RefPtr<WebCore::PlatformSpeechSynthesisUtterance> m_utterance;

    const RetainPtr<AVSpeechSynthesizer> m_synthesizer;
}

- (WebSpeechSynthesisWrapper *)initWithSpeechSynthesizer:(WebCore::PlatformSpeechSynthesizer*)synthesizer;
- (void)speakUtterance:(RefPtr<WebCore::PlatformSpeechSynthesisUtterance>&&)utterance;

@end

@implementation WebSpeechSynthesisWrapper

- (WebSpeechSynthesisWrapper *)initWithSpeechSynthesizer:(WebCore::PlatformSpeechSynthesizer*)synthesizer
{
    if (!(self = [super init]))
        return nil;

    m_synthesizerObject = synthesizer;

#if HAVE(AVSPEECHSYNTHESIS_VOICES_CHANGE_NOTIFICATION)
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(availableVoicesDidChange) name:RetainPtr { AVSpeechSynthesisAvailableVoicesDidChangeNotification }.get() object:nil];
#endif

    return self;
}

#if HAVE(AVSPEECHSYNTHESIS_VOICES_CHANGE_NOTIFICATION)

- (void)availableVoicesDidChange
{
    Ref { *m_synthesizerObject }->voicesDidChange();
}

#endif

- (float)mapSpeechRateToPlatformRate:(float)rate
{
    // WebSpeech says to go from .1 -> 10 (default 1)
    // AVSpeechSynthesizer asks for 0 -> 1 (default. 5)
    if (rate < 1)
        rate *= AVSpeechUtteranceDefaultSpeechRate;
    else
        rate = AVSpeechUtteranceDefaultSpeechRate + ((rate - 1) * (AVSpeechUtteranceMaximumSpeechRate - AVSpeechUtteranceDefaultSpeechRate));

    return rate;
}

- (void)speakUtterance:(RefPtr<WebCore::PlatformSpeechSynthesisUtterance>&&)utterance
{
    ASSERT(utterance);
    if (!utterance || !PAL::isAVFoundationFrameworkAvailable())
        return;
    
    BEGIN_BLOCK_OBJC_EXCEPTIONS
    if (!m_synthesizer) {
        lazyInitialize(m_synthesizer, adoptNS([PAL::allocAVSpeechSynthesizerInstance() init]));
        [m_synthesizer setDelegate:self];
    }
    
    // Choose the best voice, by first looking at the utterance voice, then the utterance language,
    // then choose the default language.
    RefPtr utteranceVoice = utterance->voice();
    RetainPtr<NSString> voiceLanguage;
    if (!utteranceVoice || utteranceVoice->voiceURI().isEmpty()) {
        if (utterance->lang().isEmpty())
            voiceLanguage = [PAL::getAVSpeechSynthesisVoiceClassSingleton() currentLanguageCode];
        else
            voiceLanguage = utterance->lang().createNSString();
    } else
        voiceLanguage = utterance->voice()->lang().createNSString();

    AVSpeechSynthesisVoice *avVoice = nil;
    if (utteranceVoice)
        avVoice = [PAL::getAVSpeechSynthesisVoiceClassSingleton() voiceWithIdentifier:utteranceVoice->voiceURI().createNSString().get()];

    if (!avVoice)
        avVoice = [PAL::getAVSpeechSynthesisVoiceClassSingleton() voiceWithLanguage:voiceLanguage.get()];

    RetainPtr<AVSpeechUtterance> avUtterance = [PAL::getAVSpeechUtteranceClassSingleton() speechUtteranceWithString:utterance->text().createNSString().get()];

    [avUtterance setRate:[self mapSpeechRateToPlatformRate:utterance->rate()]];
    [avUtterance setVolume:utterance->volume()];
    [avUtterance setPitchMultiplier:utterance->pitch()];
    [avUtterance setVoice:avVoice];
    utterance->setWrapper(avUtterance.get());
    m_utterance = WTF::move(utterance);

    // macOS won't send a did start speaking callback for empty strings.
#if !HAVE(UNIFIED_SPEECHSYNTHESIS_FIX_FOR_81465164)
    if (!m_utterance->text().length())
        m_synthesizerObject->client().didStartSpeaking(Ref { *m_utterance });
#endif

    [m_synthesizer speakUtterance:avUtterance.get()];
    END_BLOCK_OBJC_EXCEPTIONS
}

- (void)pause
{
    if (!m_utterance)
        return;

    BEGIN_BLOCK_OBJC_EXCEPTIONS
    [m_synthesizer pauseSpeakingAtBoundary:AVSpeechBoundaryImmediate];
    END_BLOCK_OBJC_EXCEPTIONS
}

- (void)resume
{
    if (!m_utterance)
        return;

    BEGIN_BLOCK_OBJC_EXCEPTIONS
    [m_synthesizer continueSpeaking];
    END_BLOCK_OBJC_EXCEPTIONS
}

- (void)resetState
{
    // On a reset, cancel utterance and set to nil immediately so the next speech job continues without waiting for a callback
    [self cancel];
    m_utterance = nil;
}

- (void)cancel
{
    if (!m_utterance)
        return;

    BEGIN_BLOCK_OBJC_EXCEPTIONS
    [m_synthesizer stopSpeakingAtBoundary:AVSpeechBoundaryImmediate];
    END_BLOCK_OBJC_EXCEPTIONS
}

- (void)speechSynthesizer:(AVSpeechSynthesizer *)synthesizer didStartSpeechUtterance:(AVSpeechUtterance *)utterance
{
    UNUSED_PARAM(synthesizer);
    if (!m_utterance || m_utterance->wrapper() != utterance)
        return;

    m_synthesizerObject->client().didStartSpeaking(Ref { *m_utterance });
}

- (void)speechSynthesizer:(AVSpeechSynthesizer *)synthesizer didFinishSpeechUtterance:(AVSpeechUtterance *)utterance
{
    UNUSED_PARAM(synthesizer);
    if (!m_utterance || m_utterance->wrapper() != utterance)
        return;

    // Clear the m_utterance variable in case finish speaking kicks off a new speaking job immediately.
    RefPtr<WebCore::PlatformSpeechSynthesisUtterance> protectedUtterance = m_utterance;
    m_utterance = nullptr;

    m_synthesizerObject->client().didFinishSpeaking(*protectedUtterance);
}

- (void)speechSynthesizer:(AVSpeechSynthesizer *)synthesizer didPauseSpeechUtterance:(AVSpeechUtterance *)utterance
{
    UNUSED_PARAM(synthesizer);
    if (!m_utterance || m_utterance->wrapper() != utterance)
        return;

    m_synthesizerObject->client().didPauseSpeaking(Ref { *m_utterance });
}

- (void)speechSynthesizer:(AVSpeechSynthesizer *)synthesizer didContinueSpeechUtterance:(AVSpeechUtterance *)utterance
{
    UNUSED_PARAM(synthesizer);
    if (!m_utterance || m_utterance->wrapper() != utterance)
        return;

    m_synthesizerObject->client().didResumeSpeaking(Ref { *m_utterance });
}

- (void)speechSynthesizer:(AVSpeechSynthesizer *)synthesizer didCancelSpeechUtterance:(AVSpeechUtterance *)utterance
{
    UNUSED_PARAM(synthesizer);
    if (!m_utterance || m_utterance->wrapper() != utterance)
        return;

    // Clear the m_utterance variable in case finish speaking kicks off a new speaking job immediately.
    RefPtr<WebCore::PlatformSpeechSynthesisUtterance> protectedUtterance = m_utterance;
    m_utterance = nullptr;

    m_synthesizerObject->client().didFinishSpeaking(*protectedUtterance);
}

- (void)speechSynthesizer:(AVSpeechSynthesizer *)synthesizer willSpeakRangeOfSpeechString:(NSRange)characterRange utterance:(AVSpeechUtterance *)utterance
{
    UNUSED_PARAM(synthesizer);
    if (!m_utterance || m_utterance->wrapper() != utterance)
        return;

    // AVSpeechSynthesizer only supports word boundaries.
    m_synthesizerObject->client().boundaryEventOccurred(Ref { *m_utterance }, WebCore::SpeechBoundary::SpeechWordBoundary, characterRange.location, characterRange.length);
}

@end

namespace WebCore {

Ref<PlatformSpeechSynthesizer> PlatformSpeechSynthesizer::create(PlatformSpeechSynthesizerClient& client)
{
    return adoptRef(*new PlatformSpeechSynthesizer(client));
}

PlatformSpeechSynthesizer::PlatformSpeechSynthesizer(PlatformSpeechSynthesizerClient& client)
    : m_speechSynthesizerClient(client)
{
}

PlatformSpeechSynthesizer::~PlatformSpeechSynthesizer() = default;

void PlatformSpeechSynthesizer::appendVoices(NSArray *voices)
{
    for (AVSpeechSynthesisVoice *voice in voices) {
        if (voice.isSystemVoice) {
            NSString *identifier = voice.identifier;
            NSString *displayName = voice.name;
#if PLATFORM(DRIFTSTACK)
            // V-2026-05-02: iPhone reference voice list (captured from real
            // iPhone 16 Pro / iOS 26.4.1, 68 entries) shares ALL voice
            // identifiers with Mac. The DIFFERENCE is in the display names
            // of 4 voices that iOS renamed (legacy URIs preserved):
            //   com.apple.speech.synthesis.voice.Deranged   → "Wobble"     (Mac: "Deranged")
            //   com.apple.speech.synthesis.voice.Hysterical → "Jester"     (Mac: "Hysterical")
            //   com.apple.speech.synthesis.voice.Princess   → "Superstar"  (Mac: "Princess")
            //   com.apple.speech.synthesis.voice.Organ      → "Organ"      (Mac: "Pipe Organ")
            //
            // Earlier blacklist approach was WRONG: iPhone reference HAS all
            // those novelty voices (Albert, Bad News, etc.) — only their
            // names changed for the 4 renamed entries. Filtering them out
            // broke the cumulative-rig speech.voices match.
            //
            // V-525.A.1 (2026-05-08): Samantha tier mapping per V-074 follow-up
            // was BACKWARDS. V-525 empirical proof — fork V-525 output had
            // 'compact.en-US.Samantha' while iPhone 17 / Safari 26.4 V-525.A
            // BS Automate capture has 'super-compact.en-US.Samantha'. V-074
            // comment ("iPhone uses 'compact', Mac uses 'super-compact' —
            // remap identifier") was wrong-direction. REMOVED the
            // super-compact → compact remap; iPhone reports super-compact
            // and fork now exposes whatever AVSpeechSynthesisVoice returns
            // natively (which V-525.A.1 verifies post-build).
            //
            // V-657 (2026-05-11): V-525.A.1 was empirically validated against
            // BS Automate iOS 18.6 pool ("iPhone 17" capture). The launch
            // archetype is iphone16pro_ios18_7_safari26_4 — DIFFERENT iOS
            // minor version with a DIFFERENT voice catalog. Cumrig REF
            // `iphone16pro_ios26_4_1/2026-05-04T19-24-11Z_real-iphone-recapture.json`
            // (physical iPhone iOS 18.7 / Safari 26.4) reports
            // `com.apple.voice.compact.en-US.Samantha` (NOT super-compact).
            // V-525.A.1 was correct for iOS 18.6 but wrong-direction for iOS
            // 18.7. Per memory rule "Inline iphone_reference data is SUSPECT
            // until BS-verified" → BS data was the wrong-pool source.
            //
            // V-657 super-compact → compact precise remap. Real iPhone iOS
            // 18.7 / Safari 26.4 returns most voices as super-compact (45/68)
            // but FOUR specific default-language voices are compact-tier:
            //   com.apple.voice.compact.en-US.Samantha
            //   com.apple.voice.compact.kn-IN.Alpana
            //   com.apple.voice.compact.te-IN.Geeta
            //   com.apple.voice.compact.bn-IN.Paya
            // (Empirically extracted from iphone16pro_ios26_4_1/
            // 2026-05-04T19-24-11Z_real-iphone-recapture.json.)
            // Mac returns all these as super-compact. Archetype-gated so
            // iOS-18.6 BS-pool-targeted sessions are unaffected.
            //
            // Reads DRIFTSTACK_ARCHETYPE env var directly; matches V-633.D
            // env-gate pattern; avoids cross-module header dependency.
            //
            // Wave 29-229 C-A1 attempt (REVERTED): DriftstackArchetypeConfig
            // wire failed at link time — singleton() symbol not exported by
            // SourcesCocoa.txt @nonARC @no-unify entry. Xcode project regen
            // required before C-A1 accessor wiring can land. Tracked as
            // Tier-3 founder-action.
            // 2026-06-27 sweep: live getenv, NOT static-cached (silently-inert-gate sweep).
            const bool v657NeedsCompactRemap = []() {
                const char* env = getenv("DRIFTSTACK_ARCHETYPE");
                if (!env || !env[0]) return false;
                NSString *archStr = [NSString stringWithUTF8String:env];
                return [archStr isEqualToString:@"iphone16pro_ios18_7_safari26_4"]
                    || [archStr isEqualToString:@"iphone16pro_ios26_4_1"];
            }();
            if (v657NeedsCompactRemap
                && ([identifier isEqualToString:@"com.apple.voice.super-compact.en-US.Samantha"]
                 || [identifier isEqualToString:@"com.apple.voice.super-compact.kn-IN.Alpana"]
                 || [identifier isEqualToString:@"com.apple.voice.super-compact.te-IN.Geeta"]
                 || [identifier isEqualToString:@"com.apple.voice.super-compact.bn-IN.Paya"])) {
                identifier = [identifier stringByReplacingOccurrencesOfString:@"super-compact" withString:@"compact"];
            }
            // W1414 (2026-06-07) — iphone17 launch-archetype Samantha tier (Mac-host-leak).
            // The V-657 remap above is iphone16pro-ONLY, so for the iphone17 launch archetype
            // it does NOT fire and the fork exposes the HOST Mac's Samantha tier. Since ~May 2026
            // the Mac registers Samantha as `compact` (the V-657 "Mac returns these as super-compact"
            // note is now stale, W623), but a real iPhone 17 / iOS 18.7 / Safari 26.4 reports
            // `super-compact.en-US.Samantha` — unanimous across 27 BS /aio captures (10× Version/26.4
            // + 17× 26.5; W620-624). This is a DEVICE difference, not a source conflict: iPhone 16 Pro
            // genuinely = compact (the physical V-657 REF, W621), iPhone 17 = super-compact. So this is
            // a SEPARATE archetype-gated remap, NOT a revert of V-657 (which stays correct for 16 Pro).
            // Bounded to Samantha ONLY — the other 67/68 voices already match real iphone17 natively
            // (W624; Geeta/Alpana/Paya are compact on BOTH the Mac and real iphone17). The match is on
            // the `compact` identifier so it's a no-op if a future macOS reverts Samantha to super-compact.
            // W2556 (dispatch audit #4): was an EXACT-slug match on iphone17_ios18_7_safari26_4, so
            // iphone17_ios18_7_safari26_5 + iphone17pro/promax (all iOS 18.7) got Mac-native `compact`
            // (a per-archetype voice tell). The 17× real 26.5 captures (W620-624) confirm the iPhone 17
            // FAMILY = super-compact at BOTH 26.4 and 26.5; voices are per-iOS-version so all iOS-18.7
            // 17-family models share it. Narrowed to the CONFIRMED set (iphone17* AND ios18_7).
            // W2560 (per-archetype divergence audit): EXTENDED to iphone14pro/iphone14promax @ ios18_7.
            // A real-device BS capture (reference/iphone14pro_ios26_bs/...phaseB_iphone14pro_v1_2.json —
            // model "iPhone 14 Pro", UA "iPhone OS 18_7 ... Version/26.2") reports
            // com.apple.voice.super-compact.en-US.Samantha, identical to the iPhone 17 family. So the
            // Samantha super-compact tier is NOT iphone17-exclusive at iOS 18.7 — the A16 Pro shares it.
            // Without this, the 6 supported iphone14pro/promax @ ios18_7 slugs got the host Mac's
            // `compact.en-US.Samantha` = a reference-VERIFIED wrong served value (per-archetype tell).
            // Still EXCLUDES: iphone16pro (genuinely `compact` — handled by the V-657 remap above, a
            // DIFFERENT real-device tier at the same iOS 18.7); A15 iphone14/iphone14plus (the substring
            // "iphone14pro" matches only the A16 Pro/ProMax, not the non-Pro A15); and ALL ios18_6 slugs
            // (the Samantha tier at iOS 18.6 is unverified — never assume across an iOS version, W2274).
            // 2026-06-27 sweep: live getenv, NOT static-cached (silently-inert-gate sweep).
            const bool needsSamanthaSuperCompact = []() {
                const char* env = getenv("DRIFTSTACK_ARCHETYPE");
                if (!env || !env[0]) return false;
                NSString* slug = [NSString stringWithUTF8String:env];
                // W2560-followup (2026-07-07): the Samantha tier tracks the Safari-26 VOICE BUNDLE, not the
                // hardware model — this was hypothesised in the ios18_6 note below (W620-624) and is now
                // MULTI-MODEL capture-proven. `com.apple.voice.super-compact.en-US.Samantha` is reported by
                // EVERY captured model at Safari 26.0-26.5, across BOTH the ios18_6 and ios18_7 UA tokens:
                //   iphone17 / iphone17pro / iphone17promax @ 26.0-26.5  (60+ aio captures)
                //   iphone14                                @ 26.2/26.3/26.4 (aio-iPhone_14-1782162865630/1783439553595/1782628175319)
                //   iphone15                                @ 26.2/26.3/26.4 (9× aio-iPhone_15-*, aio-iPhone_15_safari26_2-*)
                //   iphone15promax                          @ 26.4          (aio-iPhone_15_Pro_Max-1782626872115)
                // The prior enumerated predicate (iphone17|iphone14pro only) MISSED iphone14/iphone15/
                // iphone15promax @ 26.x — a capture-proven per-model voice tell. Family-A (Safari 17/18/19,
                // incl the V-657 iphone16pro@18.6 physical-ref = `compact`) ships the OLDER bundle and stays
                // compact — a "safari26" slug match excludes them automatically. Bounded to major==26 exactly
                // (NOT >=26): the sole Safari-27 evidence is contradictory beta noise (iphone14@27.0=compact vs
                // iphone16promax@27.0=super-compact, aio-iPhone_14-1782627746461 / aio-iPhone_16_Pro_Max-1782627325394)
                // and 27.x is not a shipping archetype — its tier gets captured when it ships. This is the
                // model-mechanism fix (CLAUDE rule 5) replacing the per-slug enumeration; it also covers the
                // 26.0-26.3 flip band and the iphone16pro_*_safari26_4 registered config.
                if ([slug containsString:@"safari26"])
                    return true;
                return false;
            }();
            if (needsSamanthaSuperCompact
                && [identifier isEqualToString:@"com.apple.voice.compact.en-US.Samantha"])
                identifier = @"com.apple.voice.super-compact.en-US.Samantha";
            if ([identifier isEqualToString:@"com.apple.speech.synthesis.voice.Deranged"])
                displayName = @"Wobble";
            else if ([identifier isEqualToString:@"com.apple.speech.synthesis.voice.Hysterical"])
                displayName = @"Jester";
            else if ([identifier isEqualToString:@"com.apple.speech.synthesis.voice.Princess"])
                displayName = @"Superstar";
            else if ([identifier isEqualToString:@"com.apple.speech.synthesis.voice.Organ"])
                displayName = @"Organ"; // Mac may use "Pipe Organ"; iPhone uses "Organ"
#endif
            m_voiceList.append(PlatformSpeechSynthesisVoice::create(identifier, displayName, voice.language, /* localService */ true, /* isDefault */ true));
        }
    }
}

#if PLATFORM(DRIFTSTACK)
// W2640 — per-archetype speech-voice list from a gold-truth file.
// The host Mac's AVSpeechSynthesisVoice catalog matches the LAUNCH archetype
// (iPhone 17 / Safari 26.4 = 68 voices), but Family-A iOS 18.6 ships a DIFFERENT,
// larger catalog (223 voices, BS-captured from a real iPhone 16 Pro / 18.6). The host
// path cannot produce it, so an 18.6 session served the host's ~68 = a per-archetype
// voice tell. This reader loads the BS-captured list when the launcher sets
// DRIFTSTACK_VOICES_LIST_PATH (file schema: { "voices_results": [ { "voiceURI",
// "name", "lang", "localService", "default" }, ... ] }). INERT when the env is unset
// (every current launch-env, including the launch archetype) → the host path is
// unchanged and glyphHash/cumrig are unaffected. Returns true (and fills outList) only
// on a fully-parsed, non-empty file; any error → false → caller falls through to host.
static bool driftstackTryLoadVoiceListFromFile(Vector<Ref<PlatformSpeechSynthesisVoice>>& outList)
{
    const char* path = getenv("DRIFTSTACK_VOICES_LIST_PATH");
    if (!path || !path[0])
        return false;
    RetainPtr<NSString> nsPath = [NSString stringWithUTF8String:path];
    if (!nsPath)
        return false;
    RetainPtr<NSData> data = [NSData dataWithContentsOfFile:nsPath.get()];
    if (!data)
        return false;
    NSError *error = nil;
    id root = [NSJSONSerialization JSONObjectWithData:data.get() options:0 error:&error];
    if (error || ![root isKindOfClass:[NSDictionary class]])
        return false;
    id results = [(NSDictionary *)root objectForKey:@"voices_results"];
    if (![results isKindOfClass:[NSArray class]])
        return false;
    for (id entry in (NSArray *)results) {
        if (![entry isKindOfClass:[NSDictionary class]])
            continue;
        NSString *uri = [(NSDictionary *)entry objectForKey:@"voiceURI"];
        NSString *name = [(NSDictionary *)entry objectForKey:@"name"];
        NSString *lang = [(NSDictionary *)entry objectForKey:@"lang"];
        if (![uri isKindOfClass:[NSString class]] || ![name isKindOfClass:[NSString class]] || ![lang isKindOfClass:[NSString class]])
            continue;
        id localObj = [(NSDictionary *)entry objectForKey:@"localService"];
        id defaultObj = [(NSDictionary *)entry objectForKey:@"default"];
        bool localService = [localObj isKindOfClass:[NSNumber class]] ? [localObj boolValue] : true;
        bool isDefault = [defaultObj isKindOfClass:[NSNumber class]] ? [defaultObj boolValue] : false;
        outList.append(PlatformSpeechSynthesisVoice::create(uri, name, lang, localService, isDefault));
    }
    return !outList.isEmpty();
}
#endif

void PlatformSpeechSynthesizer::initializeVoiceList()
{
#if PLATFORM(DRIFTSTACK)
    // Fills m_voiceList directly; returns false (leaving it untouched/empty) on any
    // parse error → fall through to the host AVSpeechSynthesisVoice path below.
    if (driftstackTryLoadVoiceListFromFile(m_voiceList)) {
        m_speechSynthesizerClient.voicesDidChange();
        return;
    }
#endif

    if (!PAL::isAVFoundationFrameworkAvailable())
        return;

    BEGIN_BLOCK_OBJC_EXCEPTIONS

    Class avSpeechSynthesisVoiceClass = PAL::getAVSpeechSynthesisVoiceClassSingleton();

    // Support older OS versions that don't have the asynchronous version yet.
    // Remove this once 26.3 is the minimum OS version supported by Safari.
    if (![avSpeechSynthesisVoiceClass respondsToSelector:@selector(speechVoicesIncludingSuperCompactWithCompletionHandler:)]) {
        appendVoices([avSpeechSynthesisVoiceClass speechVoicesIncludingSuperCompact]);
        return;
    }

    WeakPtr weakThis { *this };
    [avSpeechSynthesisVoiceClass speechVoicesIncludingSuperCompactWithCompletionHandler:^(NSArray<AVSpeechSynthesisVoice *> *voices) {
        callOnMainThread([weakThis, voices = RetainPtr { voices }]() {
            BEGIN_BLOCK_OBJC_EXCEPTIONS
            RefPtr protectedThis = weakThis.get();
            if (!protectedThis)
                return;

            protectedThis->appendVoices(voices.get());
            protectedThis->m_speechSynthesizerClient.voicesDidChange();
            END_BLOCK_OBJC_EXCEPTIONS
        });
    }];

    END_BLOCK_OBJC_EXCEPTIONS
}

void PlatformSpeechSynthesizer::pause()
{
    [m_platformSpeechWrapper pause];
}

void PlatformSpeechSynthesizer::resume()
{
    [m_platformSpeechWrapper resume];
}

void PlatformSpeechSynthesizer::speak(RefPtr<PlatformSpeechSynthesisUtterance>&& utterance)
{
    if (!m_platformSpeechWrapper)
        m_platformSpeechWrapper = adoptNS([[WebSpeechSynthesisWrapper alloc] initWithSpeechSynthesizer:this]);

    [m_platformSpeechWrapper speakUtterance:utterance.get()];
}

void PlatformSpeechSynthesizer::cancel()
{
    [m_platformSpeechWrapper cancel];
}

void PlatformSpeechSynthesizer::resetState()
{
    [m_platformSpeechWrapper resetState];
}

} // namespace WebCore

#endif // ENABLE(SPEECH_SYNTHESIS) && PLATFORM(COCOA)
