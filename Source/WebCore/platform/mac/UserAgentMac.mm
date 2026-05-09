/*
 * Copyright (C) 2014-2017 Apple Inc. All rights reserved.
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

#import "config.h"
#import "UserAgent.h"

#if PLATFORM(MAC)

#import <wtf/NeverDestroyed.h>
#import <wtf/text/MakeString.h>

namespace WebCore {

String standardUserAgentWithApplicationName(const String& applicationName, const String&, UserAgentType)
{
#if PLATFORM(DRIFTSTACK)
    // V-228: HTTP User-Agent header iPhone override. Wave 1.2 (V-2026-04-29)
    // overrode Navigator::userAgent() (the JS-level navigator.userAgent
    // getter) but the network-layer HTTP User-Agent header sent on outgoing
    // requests comes from this function — was returning Mac UA. Tracker probes
    // /useragent + many detection vendors read both JS UA + HTTP UA + flag
    // any divergence as "spoofing detected". Match Wave 1.2 + V-205 Bug 2
    // (WorkerNavigator) UA string here.
    static NeverDestroyed<String> driftstackHttpUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s;
    UNUSED_PARAM(applicationName);
    return driftstackHttpUA.get();
#else
    String appNameSuffix = applicationName.isEmpty() ? emptyString() : makeString(' ', applicationName);

    return makeString("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"_s, appNameSuffix);
#endif
}

} // namespace WebCore

#endif // PLATFORM(MAC)
