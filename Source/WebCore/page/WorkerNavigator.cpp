/*
 * Copyright (C) 2008-2025 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "config.h"
#include "WorkerNavigator.h"

#if PLATFORM(DRIFTSTACK)
#include "DriftstackArchetypeConfig.h"
#endif

#include "Chrome.h"
#include "ContextDestructionObserverInlines.h"
#include "GPU.h"
#include "JSDOMPromiseDeferred.h"
#include "NavigatorUAData.h"
#include "Page.h"
#include "PushEvent.h"
#include "ServiceWorkerGlobalScope.h"
#include "UserAgentStringData.h"
#include "UserAgentStringParser.h"
#include "WorkerBadgeProxy.h"
#include "WorkerGlobalScope.h"
#include "WorkerThread.h"
#include <wtf/TZoneMallocInlines.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(WorkerNavigator);

WorkerNavigator::WorkerNavigator(ScriptExecutionContext& context, const String& userAgent, bool isOnline)
    : NavigatorBase(&context)
    , m_userAgent(userAgent)
    , m_isOnline(isOnline)
{
}

WorkerNavigator::~WorkerNavigator() = default;

const String& WorkerNavigator::userAgent() const
{
#if PLATFORM(DRIFTSTACK)
    // V-205 Bug 2 (founder ack 2026-05-05 V-203 escalation): Wave 1.2
    // UA override applied to main-thread Navigator only. Workers
    // inherited Mac WebKit default UA, producing cross-context
    // divergence (CreepJS catches main UA != worker UA instantly).
    // Override here too so all contexts return the same iPhone UA.
    //
    // Wave 29-360 item 1 + Wave 29-389.B (Config singleton migration):
    // 3-layer UA resolution priority — mirrors Navigator.cpp exactly so
    // main/worker UA stay in sync per V-205 Bug 2:
    //   1. DriftstackArchetypeConfig singleton if valid + non-empty
    //   2. DRIFTSTACK_ARCHETYPE_UA_FULL env-var (back-compat)
    //   3. V-202/Wave 1.2 hardcoded launch-archetype default
    static NeverDestroyed<String> driftstackResolvedUA = []() {
        auto& cfg = DriftstackArchetypeConfig::singleton();
        if (cfg.isValid()) {
            String s = cfg.userAgentFull();
            if (!s.isEmpty())
                return s;
        }
        const char* env = getenv("DRIFTSTACK_ARCHETYPE_UA_FULL");
        if (env && env[0])
            return String::fromUTF8(env);
        // Wave 29-404 §11.A.5 archetype-slug-to-UA fallback for Worker
        // context (mirrors Navigator.cpp).
        const char* slug = getenv("DRIFTSTACK_ARCHETYPE");
        if (slug && slug[0]) {
            std::string_view sv(slug);
            if (sv == "iphone16pro_ios18_6_safari18_6")
                return String("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"_s);
            if (sv == "iphone17_ios18_7_safari26_4")
                return String("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s);
            if (sv == "iphone16pro_ios18_7_safari26_4")
                return String("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s);
        }
        return String();
    }();
    if (!driftstackResolvedUA.get().isEmpty())
        return driftstackResolvedUA.get();
    static NeverDestroyed<String> driftstackDefaultUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s;
    return driftstackDefaultUA.get();
#endif
    return m_userAgent;
}

bool WorkerNavigator::onLine() const
{
    return m_isOnline;
}

GPU* WorkerNavigator::gpu()
{
#if HAVE(WEBGPU_IMPLEMENTATION)
#if PLATFORM(DRIFTSTACK)
    // Wave 29-402 v1.0 navigator.gpu Family A hide (Worker context mirror;
    // founder verdict 2026-05-19). See Navigator.cpp:412 for full rationale.
    static bool s_isFamilyAWorker = []() {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype) return false;
        return std::string_view(archetype).find("safari18_") != std::string_view::npos;
    }();
    if (s_isFamilyAWorker)
        return nullptr;
#endif
    if (!m_gpuForWebGPU) {
        Ref context = downcast<WorkerGlobalScope>(*this->scriptExecutionContext());
        if (!context->graphicsClient())
            return nullptr;

        RefPtr gpu = context->graphicsClient()->createGPUForWebGPU();
        if (!gpu)
            return nullptr;

        m_gpuForWebGPU = GPU::create(*gpu);
    }

    return m_gpuForWebGPU.get();
#else
    return nullptr;
#endif
}

void WorkerNavigator::setAppBadge(std::optional<unsigned long long> badge, Ref<DeferredPromise>&& promise)
{
#if ENABLE(DECLARATIVE_WEB_PUSH)
    if (auto* context = dynamicDowncast<ServiceWorkerGlobalScope>(scriptExecutionContext())) {
        if (auto* declarativePushEvent = context->declarativePushEvent()) {
            declarativePushEvent->setUpdatedAppBadge(WTF::move(badge));
            return;
        }
    }
#endif // ENABLE(DECLARATIVE_WEB_PUSH)

    RefPtr scope = downcast<WorkerGlobalScope>(scriptExecutionContext());
    if (!scope) {
        promise->reject(ExceptionCode::InvalidStateError);
        return;
    }

    if (CheckedPtr workerBadgeProxy = scope->thread()->workerBadgeProxy())
        workerBadgeProxy->setAppBadge(badge);
    promise->resolve();
}

void WorkerNavigator::clearAppBadge(Ref<DeferredPromise>&& promise)
{
    setAppBadge(0, WTF::move(promise));
}

NavigatorUAData& WorkerNavigator::userAgentData() const
{
    Ref parser = UserAgentStringParser::create(m_userAgent);
    std::optional userAgentStringData = parser->parse();
    if (userAgentStringData) {
        m_navigatorUAData = NavigatorUAData::create(WTF::move(*userAgentStringData));
        return *m_navigatorUAData;
    }

    m_navigatorUAData = NavigatorUAData::create();
    return *m_navigatorUAData;
};

} // namespace WebCore
