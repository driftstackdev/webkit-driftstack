/*
 * Copyright (C) 2017 Google Inc. All rights reserved.
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
#include "VisualViewport.h"

#include "Chrome.h"
#include "ChromeClient.h"
#include "ContextDestructionObserver.h"
#if PLATFORM(DRIFTSTACK)
#include "DriftstackArchetypeConfig.h"
#endif
#include "DocumentPage.h"
#include "DocumentView.h"
#include "Event.h"
#include "EventNames.h"
#include "EventTargetInterfaces.h"
#include "LocalDOMWindow.h"
#include "LocalFrameInlines.h"
#include "LocalFrameView.h"
#include <wtf/TZoneMallocInlines.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(VisualViewport);

VisualViewport::VisualViewport(LocalDOMWindow& window)
    : LocalDOMWindowProperty(&window)
{
}

enum EventTargetInterfaceType VisualViewport::eventTargetInterface() const
{
    return EventTargetInterfaceType::VisualViewport;
}

ScriptExecutionContext* VisualViewport::scriptExecutionContext() const
{
    auto* window = this->window();
    return window ? window->document() : nullptr;
}

bool VisualViewport::addEventListener(const AtomString& eventType, Ref<EventListener>&& listener, const AddEventListenerOptions& options)
{
    if (!EventTarget::addEventListener(eventType, WTF::move(listener), options))
        return false;

    if (RefPtr frame = this->frame())
        frame->document()->addListenerTypeIfNeeded(eventType);
    return true;
}

void VisualViewport::updateFrameLayout() const
{
    ASSERT(frame());
    frame()->document()->updateLayout({ LayoutOptions::IgnorePendingStylesheets, LayoutOptions::RunPostLayoutTasksSynchronously });
}

double VisualViewport::offsetLeft() const
{
    if (!frame())
        return 0;

    updateFrameLayout();
    return m_offsetLeft;
}

double VisualViewport::offsetTop() const
{
    if (!frame())
        return 0;

    updateFrameLayout();
    return m_offsetTop;
}

double VisualViewport::pageLeft() const
{
    if (!frame())
        return 0;

    updateFrameLayout();
    return m_pageLeft;
}

double VisualViewport::pageTop() const
{
#if PLATFORM(DRIFTSTACK)
    // Driftstack: visualViewport reflects the iPhone-archetype layout
    // viewport regardless of MiniBrowser's actual NSWindow geometry.
    // pageTop is scroll-relative; iPhone reference captured at scroll 0.
    return 0;
#else
    if (!frame())
        return 0;

    updateFrameLayout();
    return m_pageTop;
#endif
}

double VisualViewport::width() const
{
#if PLATFORM(DRIFTSTACK)
    // V-074 + W2266: visualViewport.width === the CSS layout-viewport width === screen.width
    // (device-width). Derive from the archetype Config (matching innerWidth/outerWidth/availWidth)
    // so the matrix stays coherent — a hardcoded 402 mismatches screen.width for any non-402-wide
    // model. Launch archetype (iphone17) Config=402, unchanged. (height() stays Safari-version-keyed
    // at 714/678 — the chrome-adjusted visible height, NOT screen.height.)
    if (auto w = DriftstackArchetypeConfig::singleton().screenWidth(); w > 0)
        return static_cast<double>(w);
    return 402;
#else
    if (!frame())
        return 0;

    updateFrameLayout();
    return m_width;
#endif
}

double VisualViewport::height() const
{
#if PLATFORM(DRIFTSTACK)
    // V-074 + W2275: visualViewport.height == innerHeight (verified equal on real iPhone, all
    // models). PREFER the per-(model,Safari-version) real-device inner_height from the archetype
    // Config (model-specific chrome — W2274); fall back to the Safari-version-keyed 678/714 when
    // the Config doesn't carry it. Mirrors LocalDOMWindow::innerHeight() exactly.
    if (auto ih = DriftstackArchetypeConfig::singleton().innerHeight(); ih > 0)
        return static_cast<double>(ih);
    static double s_height = []() -> double {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype || !archetype[0])
            return 714.0;
        std::string_view sv { archetype };
        if (sv.find("safari17_") != std::string_view::npos
            || sv.find("safari18_") != std::string_view::npos
            || sv.find("safari19_") != std::string_view::npos
            || sv.find("safari26_0") != std::string_view::npos
            || sv.find("safari26_1") != std::string_view::npos
            || sv.find("safari26_2") != std::string_view::npos
            || sv.find("safari26_3") != std::string_view::npos)
            return 678.0;
        return 714.0;
    }();
    return s_height;
#else
    if (!frame())
        return 0;

    updateFrameLayout();
    return m_height;
#endif
}

double VisualViewport::scale() const
{
    // Subframes always have scale 1 since they aren't scaled relative to their parent frame.
    RefPtr frame = this->frame();
    if (!frame || !frame->isMainFrame())
        return 1;

    updateFrameLayout();
    return m_scale;
}

void VisualViewport::update()
{
    double offsetLeft = 0;
    double offsetTop = 0;
    m_pageLeft = 0;
    m_pageTop = 0;
    double width = 0;
    double height = 0;
    double scale = 1;

    RefPtr frame = this->frame();
    if (frame) {
        if (RefPtr view = frame->view()) {
            auto visualViewportRect = view->visualViewportRect();
            auto layoutViewportRect = view->layoutViewportRect();
            auto pageZoomFactor = frame->pageZoomFactor();
            ASSERT(pageZoomFactor);
            offsetLeft = (visualViewportRect.x() - layoutViewportRect.x()) / pageZoomFactor;
            offsetTop = (visualViewportRect.y() - layoutViewportRect.y()) / pageZoomFactor;
            m_pageLeft = visualViewportRect.x() / pageZoomFactor;
            m_pageTop = visualViewportRect.y() / pageZoomFactor;
            width = visualViewportRect.width() / pageZoomFactor;
            height = visualViewportRect.height() / pageZoomFactor;
        }
        if (RefPtr page = frame->page())
            scale = page->pageScaleFactor() / page->chrome().client().baseViewportLayoutSizeScaleFactor();
    }

    RefPtr<Document> document = frame ? frame->document() : nullptr;
    if (m_offsetLeft != offsetLeft || m_offsetTop != offsetTop) {
        if (document)
            document->setNeedsVisualViewportScrollEvent();
        m_offsetLeft = offsetLeft;
        m_offsetTop = offsetTop;
    }
    if (m_width != width || m_height != height) {
        if (document)
            document->setNeedsVisualViewportResize();
        m_width = width;
        m_height = height;
        m_scale = scale;
    }
}

} // namespace WebCore
