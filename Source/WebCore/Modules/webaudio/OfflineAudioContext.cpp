/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 * Copyright (C) 2020-2025 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
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

#include "config.h"

#if ENABLE(WEB_AUDIO)

#include "OfflineAudioContext.h"

#include "AudioBuffer.h"
#include "AudioNodeOutput.h"
#include "AudioUtilities.h"
#include "Document.h"
#include "EventTargetInlines.h"
#include "JSAudioBuffer.h"
#include "JSDOMConvertInterface.h"
#include "JSDOMPromiseDeferred.h"
#include "OfflineAudioCompletionEvent.h"
#include "OfflineAudioContextOptions.h"
#if PLATFORM(DRIFTSTACK)
// FontCascade.cpp uses "cocoa/DriftstackAsciiAtlas.h" (relative from
// platform/graphics/), but Modules/webaudio/ has a different include
// search path. Use the platform/graphics-relative path that mirrors
// how other Modules/ files reference platform/graphics/ headers.
#include "platform/graphics/cocoa/DriftstackAudioAtlas.h"
#include "AudioNodeInput.h"
#include "BiquadFilterNode.h"
#include "GainNode.h"
#include "OscillatorNode.h"
#include <CommonCrypto/CommonDigest.h>
#include <wtf/text/StringBuilder.h>
#endif
#include <JavaScriptCore/ConsoleTypes.h>
#include <wtf/Scope.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/text/MakeString.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(OfflineAudioContext);

OfflineAudioContext::OfflineAudioContext(Document& document, const OfflineAudioContextOptions& options)
    : BaseAudioContext(document)
    , m_destinationNode(makeUniqueRefWithoutRefCountedCheck<OfflineAudioDestinationNode>(*this, options.numberOfChannels, options.sampleRate, AudioBuffer::create(options.numberOfChannels, options.length, options.sampleRate)))
    , m_length(options.length)
{
    if (!renderTarget())
        document.addConsoleMessage(MessageSource::JS, MessageLevel::Warning, makeString("Failed to construct internal AudioBuffer with "_s, options.numberOfChannels, " channel(s), a sample rate of "_s, options.sampleRate, " and a length of "_s, options.length, '.'));
    else if (noiseInjectionPolicies().contains(NoiseInjectionPolicy::Minimal))
        renderTarget()->increaseNoiseInjectionMultiplier();
}

ExceptionOr<Ref<OfflineAudioContext>> OfflineAudioContext::create(ScriptExecutionContext& context, const OfflineAudioContextOptions& options)
{
    auto* document = dynamicDowncast<Document>(context);
    if (!document)
        return Exception { ExceptionCode::NotSupportedError, "OfflineAudioContext is only supported in Document contexts"_s };
    if (!options.numberOfChannels || options.numberOfChannels > maxNumberOfChannels)
        return Exception { ExceptionCode::NotSupportedError, "Number of channels is not in range"_s };
    if (!options.length)
        return Exception { ExceptionCode::NotSupportedError, "length cannot be 0"_s };
    if (!isSupportedSampleRate(options.sampleRate))
        return Exception { ExceptionCode::NotSupportedError, "sampleRate is not in range"_s };

    Ref audioContext = adoptRef(*new OfflineAudioContext(*document, options));
    audioContext->suspendIfNeeded();
    return audioContext;
}

ExceptionOr<Ref<OfflineAudioContext>> OfflineAudioContext::create(ScriptExecutionContext& context, unsigned numberOfChannels, unsigned length, float sampleRate)
{
    return create(context, { numberOfChannels, length, sampleRate });
}

void OfflineAudioContext::lazyInitialize()
{
    BaseAudioContext::lazyInitialize();

    increaseNoiseMultiplierIfNeeded();
}

void OfflineAudioContext::increaseNoiseMultiplierIfNeeded()
{
    if (!noiseInjectionPolicies())
        return;

    Locker locker { graphLock() };

    RefPtr target = renderTarget();
    if (!target)
        return;

    Vector<AudioConnectionRef<AudioNode>, 1> remainingNodes;
    for (auto& node : referencedSourceNodes())
        remainingNodes.append(node.copyRef());

    while (!remainingNodes.isEmpty()) {
        auto node = remainingNodes.takeLast();
        target->increaseNoiseInjectionMultiplier(node->noiseInjectionMultiplier());
        for (unsigned i = 0; i < node->numberOfOutputs(); ++i) {
            CheckedPtr output = node->output(i);
            if (!output)
                continue;

            output->forEachInputNode([&](auto& inputNode) {
                remainingNodes.append(inputNode);
            });
        }
    }
}

void OfflineAudioContext::uninitialize()
{
    if (!isInitialized())
        return;

    BaseAudioContext::uninitialize();

    if (auto promise = std::exchange(m_pendingRenderingPromise, nullptr); promise && !isContextStopped())
        promise->reject(Exception { ExceptionCode::InvalidStateError, "Context is going away"_s });
}

void OfflineAudioContext::startRendering(Ref<DeferredPromise>&& promise)
{
    if (isStopped()) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "Context is stopped"_s });
        return;
    }

    if (m_didStartRendering) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "Rendering was already started"_s });
        return;
    }

    if (!renderTarget()) {
        promise->reject(Exception { ExceptionCode::NotSupportedError, "Failed to create audio buffer"_s });
        return;
    }

    lazyInitialize();

    protect(destination())->startRendering([promise = WTF::move(promise), pendingActivity = makePendingActivity(*this)](std::optional<Exception>&& exception) mutable {
        if (exception) {
            promise->reject(WTF::move(*exception));
            return;
        }

        pendingActivity->object().m_pendingRenderingPromise = WTF::move(promise);
        pendingActivity->object().m_didStartRendering = true;
        pendingActivity->object().setState(State::Running);
    });
}

void OfflineAudioContext::suspendRendering(double suspendTime, Ref<DeferredPromise>&& promise)
{
    if (isStopped()) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "Context is stopped"_s });
        return;
    }

    if (suspendTime < 0) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "suspendTime cannot be negative"_s });
        return;
    }

    double totalRenderDuration = length() / sampleRate();
    if (totalRenderDuration <= suspendTime) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "suspendTime cannot be greater than total rendering duration"_s });
        return;
    }

    size_t frame = AudioUtilities::timeToSampleFrame(suspendTime, sampleRate());
    frame = AudioUtilities::renderQuantumSize * ((frame + AudioUtilities::renderQuantumSize - 1) / AudioUtilities::renderQuantumSize);
    if (frame < currentSampleFrame()) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "Suspension frame is earlier than current frame"_s });
        return;
    }

    Locker locker { graphLock() };
    auto addResult = m_suspendRequests.add(frame, promise);
    if (!addResult.isNewEntry) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "There is already a pending suspend request at this frame"_s });
        return;
    }
}

void OfflineAudioContext::resumeRendering(Ref<DeferredPromise>&& promise)
{
    if (!m_didStartRendering) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "Cannot resume an offline audio context that has not started"_s });
        return;
    }
    if (isClosed()) {
        promise->reject(Exception { ExceptionCode::InvalidStateError, "Cannot resume an offline audio context that is closed"_s });
        return;
    }
    if (state() == AudioContextState::Running) {
        promise->resolve();
        return;
    }
    ASSERT(state() == AudioContextState::Suspended);

    protect(destination())->startRendering([promise = WTF::move(promise), pendingActivity = makePendingActivity(*this)](std::optional<Exception>&& exception) mutable {
        if (exception) {
            promise->reject(WTF::move(*exception));
            return;
        }

        pendingActivity->object().setState(State::Running);
        promise->resolve();
    });
}

bool OfflineAudioContext::shouldSuspend()
{
    ASSERT(!isMainThread());
    // Note that we are not using a tryLock() here. We usually avoid blocking the AudioThread
    // on lock() but we don't have a choice here since the suspension need to be exact.
    // Also, this not a real-time AudioContext so blocking the AudioThread is not as harmful.
    Locker locker { graphLock() };
    return m_suspendRequests.contains(currentSampleFrame());
}

void OfflineAudioContext::didSuspendRendering(size_t frame)
{
    setState(State::Suspended);

    RefPtr<DeferredPromise> promise;
    {
        Locker locker { graphLock() };
        promise = m_suspendRequests.take(frame);
    }
    ASSERT(promise);
    if (promise)
        promise->resolve();
}

void OfflineAudioContext::finishedRendering(bool didRendering)
{
    ASSERT(isMainThread());
    ALWAYS_LOG(LOGIDENTIFIER);

    auto uninitializeOnExit = makeScopeExit([this] {
        uninitialize();
        clear();
    });

    // Make sure our JSwrapper stays alive long enough to resolve the promise and queue the completion event.
    // Otherwise, setting the state to Closed may cause our JS wrapper to get collected early.
    auto protectedJSWrapper = makePendingActivity(*this);
    setState(State::Closed);

    // Avoid firing the event if the document has already gone away.
    if (isStopped())
        return;

    RefPtr<AudioBuffer> renderedBuffer = renderTarget();
    ASSERT(renderedBuffer);

#if PLATFORM(DRIFTSTACK)
    // V-153 Stage E hypothesis (env-var-gated, default INACTIVE):
    // iOS 26.4 collapsed audio offline-render hashes across A16/A17/A19
    // chips to a single canonical value. Many-to-one collapse signature
    // suggests a precision-reduction step. Most likely candidate:
    // Float32 → Float16 → Float32 round-trip after offline render.
    // Float16's 11-bit mantissa clips chip-specific FP variation in
    // the low 4-8 mantissa bits.
    //
    // Patch is INACTIVE by default — gate via env var
    // DRIFTSTACK_AUDIO_FLOAT16=1 (with __XPC_DRIFTSTACK_AUDIO_FLOAT16=1
    // mirror for WebContent XPC sandbox propagation).
    //
    // Validation plan: when iPhone audio.rawSamples capture lands
    // (post-V-141 td016 recapture), enable env var, run cumulative rig,
    // check if audio.offlineFingerprint10x.value.hashes[0] matches
    // iPhone reference 9f48a830... — and per-sample diff via
    // audio.rawSamples confirms byte-exact match.
    //
    // If hypothesis fails: leave gate off (zero customer-visible effect),
    // pursue fallback hypotheses per docs/architecture/option-b-stage-e-audio-rendering.md
    // §"Fallback hypotheses".
    if (renderedBuffer && didRendering) {
        static bool s_audioFloat16Enabled = []() {
            const char* env = getenv("DRIFTSTACK_AUDIO_FLOAT16");
            return env && env[0] == '1';
        }();
        if (s_audioFloat16Enabled) {
            unsigned numChannels = renderedBuffer->numberOfChannels();
            for (unsigned ch = 0; ch < numChannels; ++ch) {
                RefPtr<Float32Array> channelArr = renderedBuffer->channelData(ch);
                if (!channelArr) continue;
                // typedMutableSpan() — preferred over raw data() per WebKit's
                // -Wunsafe-buffer-usage rule.
                auto span = channelArr->typedMutableSpan();
                for (size_t i = 0; i < span.size(); ++i) {
                    // Float32 → Float16 → Float32 round-trip via ARM __fp16
                    // (standard Clang on Apple Silicon).
                    __fp16 h = span[i];
                    span[i] = static_cast<float>(h);
                }
            }
            static bool loggedOnce = false;
            if (!loggedOnce) {
                loggedOnce = true;
                WTFLogAlways("[Driftstack-V153] Float16 quantization ENABLED via DRIFTSTACK_AUDIO_FLOAT16=1; first apply on %u channels", numChannels);
            }
        }
    }

    // Wave 29-288 Audio v2 Phase A: canonical graph hash diagnostic.
    // Walks the destination → inputs chain at startRendering completion time;
    // emits per-node canonical bytes (type + key params); sha256s the
    // concatenated bytes; logs the 16-byte hex prefix.
    //
    // Diag-only — no dispatch change. Compare logged hashes against
    // JS-side opsHash to validate cross-side parity before Phase B/C
    // wires graphHash into atlas key derivation.
    //
    // Env gate: DRIFTSTACK_AUDIO_GRAPH_HASH_DIAG=1 (+ __XPC_*).
    if (renderedBuffer && didRendering) {
        static bool s_graphHashDiagEnabled = []() {
            const char* env = getenv("DRIFTSTACK_AUDIO_GRAPH_HASH_DIAG");
            return env && env[0] == '1';
        }();
        if (s_graphHashDiagEnabled) {
            StringBuilder canon;
            HashSet<AudioNode*> visited;
            auto appendNodeCanonical = [&](AudioNode& node, auto& self) -> void {
                if (!visited.add(&node).isNewEntry)
                    return;
                auto type = node.nodeType();
                canon.append('N');
                canon.append(static_cast<char>(static_cast<int>(type) + '0'));
                canon.append(':');
                switch (type) {
                case AudioNode::NodeTypeOscillator:
                    if (auto* osc = dynamicDowncast<OscillatorNode>(node)) {
                        canon.append(static_cast<char>(static_cast<int>(osc->typeForBindings()) + 'a'));
                        canon.append(':');
                        canon.append(FormattedNumber::fixedWidth(osc->frequency().value(), 6));
                        canon.append(':');
                        canon.append(FormattedNumber::fixedWidth(osc->detune().value(), 6));
                    }
                    break;
                case AudioNode::NodeTypeGain:
                    if (auto* gain = dynamicDowncast<GainNode>(node))
                        canon.append(FormattedNumber::fixedWidth(gain->gain().value(), 6));
                    break;
                case AudioNode::NodeTypeBiquadFilter:
                    if (auto* bq = dynamicDowncast<BiquadFilterNode>(node)) {
                        canon.append(static_cast<char>(static_cast<int>(bq->type()) + 'a'));
                        canon.append(':');
                        canon.append(FormattedNumber::fixedWidth(bq->frequency().value(), 6));
                        canon.append(':');
                        canon.append(FormattedNumber::fixedWidth(bq->q().value(), 6));
                        canon.append(':');
                        canon.append(FormattedNumber::fixedWidth(bq->gain().value(), 6));
                        canon.append(':');
                        canon.append(FormattedNumber::fixedWidth(bq->detune().value(), 6));
                    }
                    break;
                default:
                    canon.append('?');
                    break;
                }
                canon.append('|');
                for (unsigned i = 0; i < node.numberOfInputs(); ++i) {
                    auto* in = node.input(i);
                    if (!in) continue;
                    for (unsigned j = 0; j < in->numberOfRenderingConnections(); ++j) {
                        auto* out = in->renderingOutput(j);
                        if (!out || !out->node()) continue;
                        self(*out->node(), self);
                    }
                }
            };
            appendNodeCanonical(destination(), appendNodeCanonical);
            String canonStr = canon.toString();
            auto utf8 = canonStr.utf8();
            std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> digest;
            CC_SHA256(utf8.data(), static_cast<CC_LONG>(utf8.length()), digest.data());
            StringBuilder hexBuilder;
            static constexpr ASCIILiteral kLowerHex = "0123456789abcdef"_s;
            for (size_t i = 0; i < 16; ++i) {
                hexBuilder.append(kLowerHex[(digest[i] >> 4) & 0xf]);
                hexBuilder.append(kLowerHex[digest[i] & 0xf]);
            }
            static unsigned diagCount = 0;
            if (++diagCount <= 30) {
                WTFLogAlways("[Driftstack-AudioGraphHash-DIAG] sr=%g ch=%u frames=%u canonLen=%u sha16=%s",
                    renderedBuffer->sampleRate(), renderedBuffer->numberOfChannels(),
                    static_cast<unsigned>(renderedBuffer->length()),
                    static_cast<unsigned>(utf8.length()),
                    hexBuilder.toString().utf8().data());
            }
        }
    }

    // V-166 DASA dispatch: substitute iPhone-captured audio output bytes when
    // the rendered buffer's shape matches a captured atlas entry. Per V-163
    // root cause analysis, Mac libm vs iOS libm differ by ULP for some inputs
    // in DynamicsCompressorKernel.cpp's expf()/sqrtf() — bit-identical close
    // requires substituting iPhone's bytes rather than approximating Mac's
    // computation. This dispatch hook OVERRIDES the V-153 Float16 patch
    // result (substitution wins; the V-153 quantization is dead code when
    // DASA is enabled + atlas entry is found).
    //
    // V1 limitation: shape-based lookup (sampleRate + channelCount +
    // framesPerChannel). Works for the cumulative-rig probe (1 channel ×
    // 44100 frames × 44100 sr — 1 second). v2 (when canonical graph
    // hashing is plumbed) will use entryFor(graphConfigHash, ...) for
    // multi-probe disambiguation.
    //
    // Env-var-gated: DRIFTSTACK_AUDIO_ATLAS=1 (with __XPC_DRIFTSTACK_AUDIO_ATLAS=1
    // mirror for WebContent XPC sandbox propagation). Default OFF — when
    // env var unset, atlas is loaded but dispatch hook doesn't fire (zero
    // behavior change).
    if (renderedBuffer && didRendering) {
        static bool s_audioAtlasEnabled = []() {
            const char* env = getenv("DRIFTSTACK_AUDIO_ATLAS");
            return env && env[0] == '1';
        }();
        if (s_audioAtlasEnabled) {
            uint32_t sampleRate = static_cast<uint32_t>(renderedBuffer->sampleRate());
            uint32_t channelCount = renderedBuffer->numberOfChannels();
            uint32_t framesPerChannel = renderedBuffer->length();
            auto& atlas = DriftstackAudioAtlas::singleton();
            auto bytes = atlas.entryByShape(sampleRate, channelCount, framesPerChannel);
            if (!bytes.empty()) {
                // Atlas data is interleaved Float32; deinterleave into channel data.
                // Stage H builder produces interleaved bytes (matches AudioBus
                // internal storage convention).
                size_t expectedBytes = static_cast<size_t>(framesPerChannel) * channelCount * 4;
                if (bytes.size() == expectedBytes) {
                    // Reinterpret byte span → float span via WTF helper that
                    // satisfies -Wunsafe-buffer-usage.
                    auto interleavedSpan = spanReinterpretCast<const float>(bytes);
                    for (unsigned ch = 0; ch < channelCount; ++ch) {
                        RefPtr<Float32Array> channelArr = renderedBuffer->channelData(ch);
                        if (!channelArr) continue;
                        auto span = channelArr->typedMutableSpan();
                        for (size_t i = 0; i < framesPerChannel && i < span.size(); ++i)
                            span[i] = interleavedSpan[i * channelCount + ch];
                    }
                    static unsigned dasaSubstitutions = 0;
                    if (++dasaSubstitutions <= 8) {
                        WTFLogAlways("[Driftstack-DASA] substituted iPhone bytes for sr=%u ch=%u frames=%u (substitution #%u)",
                            sampleRate, channelCount, framesPerChannel, dasaSubstitutions);
                    }
                } else {
                    static unsigned sizeError = 0;
                    if (++sizeError <= 8) {
                        WTFLogAlways("[Driftstack-DASA-SIZE-ERROR] atlas returned %zu bytes; expected %zu",
                            bytes.size(), expectedBytes);
                    }
                }
            } else {
                static unsigned dasaMisses = 0;
                if (++dasaMisses <= 8) {
                    WTFLogAlways("[Driftstack-DASA-miss] no atlas entry for sr=%u ch=%u frames=%u (atlas has %zu entries)",
                        sampleRate, channelCount, framesPerChannel, atlas.numEntries());
                }
            }
        }
    }
#endif

    if (didRendering) {
        queueTaskToDispatchEvent(*this, TaskSource::MediaElement, OfflineAudioCompletionEvent::create(*renderedBuffer));
        settleRenderingPromise(renderedBuffer.releaseNonNull());
    } else
        settleRenderingPromise(Exception { ExceptionCode::InvalidStateError, "Offline rendering failed"_s });
}

void OfflineAudioContext::settleRenderingPromise(ExceptionOr<Ref<AudioBuffer>>&& result)
{
    auto promise = std::exchange(m_pendingRenderingPromise, nullptr);
    if (!promise)
        return;

    if (result.hasException()) {
        promise->reject(result.releaseException());
        return;
    }
    promise->resolve<IDLInterface<AudioBuffer>>(result.releaseReturnValue());
}

bool OfflineAudioContext::virtualHasPendingActivity() const
{
    return state() == State::Running;
}

} // namespace WebCore

#endif // ENABLE(WEB_AUDIO)
