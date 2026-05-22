/*
 * DriftstackTurn.mm — Wave 29-499.149 (Task #104 Phase 5)
 *
 * Phase 5 scaffold. driftstackTurnAllocate is a stub returning failure
 * until full STUN/TURN protocol implementation lands.
 *
 * Full Phase 5 implementation tracked in DriftstackTurn.h header.
 */

#import "config.h"
#import "DriftstackTurn.h"

#if PLATFORM(DRIFTSTACK)

#import <stdlib.h>
#import <wtf/Assertions.h>

namespace WebKit {

DriftstackTurnAllocation driftstackTurnAllocate(const DriftstackTurnConfig& /*config*/)
{
    DriftstackTurnAllocation alloc;
    alloc.ok = false;
    alloc.errorMessage = "Phase 5 TURN allocate not yet implemented"_s;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.149] TURN allocate scaffold — STUN/TURN protocol encoder + HMAC-SHA1 MESSAGE-INTEGRITY + auth retry are Phase 5.x work-items.");
    }
    return alloc;
}

bool driftstackTurnEnabled()
{
    const char* env = getenv("DRIFTSTACK_PATHB_V2_TURN");
    return env && env[0] == '1';
}

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
