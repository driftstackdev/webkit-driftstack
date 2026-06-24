/*
 * Copyright (C) 2018 Apple Inc. All rights reserved.
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
#import "GlobalFindInPageState.h"

#import <wtf/text/WTFString.h>

// W2870 (isolation audit, find-in-page cross-session leak): on the Mac-worker build PLATFORM(MAC) is true, so
// upstream's findPasteboard() writes/reads the SYSTEM-WIDE, per-user shared board [NSPasteboard
// pasteboardWithName:NSPasteboardNameFind]. Every session's find-in-page query string would land on that one
// board — readable/overwritable by all co-tenant sessions on the host + the operator, and the value persists
// after a session is torn down. Unlike the DOM general clipboard (W2858, which routes to a per-session NAMED
// board), the find state is global UIProcess state and each Driftstack session is its OWN UIProcess, so the
// simplest correct isolation is the per-process static (exactly the non-MAC code path): the find string lives
// only in this process's memory, is unreachable by any other session, and is reclaimed when the process exits.
// Gate the static for the Driftstack build; leave upstream's shared-board path untouched for plain Mac builds.
#if PLATFORM(MAC) && !PLATFORM(DRIFTSTACK)
#import <AppKit/NSPasteboard.h>
#import <WebCore/LegacyNSPasteboardTypes.h>
#endif

namespace WebKit {

#if PLATFORM(MAC) && !PLATFORM(DRIFTSTACK)

static RetainPtr<NSPasteboard> findPasteboard()
{
    return [NSPasteboard pasteboardWithName:NSPasteboardNameFind];
}

#else

static String& globalStringForFind()
{
    static NeverDestroyed<String> string;
    return string.get();
}

#endif

void updateStringForFind(const String& string)
{
#if PLATFORM(MAC) && !PLATFORM(DRIFTSTACK)
    [findPasteboard() setString:string.createNSString().get() forType:WebCore::legacyStringPasteboardTypeSingleton()];
#else
    globalStringForFind() = string;
#endif
}

String stringForFind()
{
#if PLATFORM(MAC) && !PLATFORM(DRIFTSTACK)
    return [findPasteboard() stringForType:WebCore::legacyStringPasteboardTypeSingleton()];
#else
    return globalStringForFind();
#endif
}

} // namespace WebKit
