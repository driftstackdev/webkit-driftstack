/*
 * Copyright (C) 2026 Driftstack. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#if PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)

#include <cstdlib>
#include <cstring>

namespace WebCore {

// A process-stable seed for the synthetic sensor streams. One WebContent process
// == one session, so this is per-session. Derived from DRIFTSTACK_SESSION_ID when
// the harness sets it (so the per-session resting pose / noise envelope VARIES per
// session per DM2 — fixed cross-session pose is the tell), else a stable fallback
// so the stream is still deterministic/testable within the process. The two
// clients (motion + orientation) XOR a per-domain salt into this so their derived
// attitudes are independent but each is stable for the session.
inline unsigned driftstackSensorSessionSeed()
{
    static const unsigned s_seed = []() -> unsigned {
        const char* sessionId = getenv("DRIFTSTACK_SESSION_ID");
        if (sessionId && sessionId[0]) {
            // FNV-1a over the session id → a stable per-session 32-bit seed.
            unsigned hash = 2166136261u;
            for (const char* p = sessionId; *p; ++p) {
                hash ^= static_cast<unsigned char>(*p);
                hash *= 16777619u;
            }
            return hash ? hash : 1u;
        }
        // No session id (dev/MiniBrowser): a fixed non-zero fallback keeps the
        // synthetic stream deterministic & reproducible for tests.
        return 0x44535453u; // "DSTS"
    }();
    return s_seed;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)
