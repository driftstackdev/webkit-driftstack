/*
 * Copyright (C) 1999-2000 Harri Porten (porten@kde.org)
 * Copyright (C) 2006-2023 Apple Inc. All rights reserved.
 * Copyright (C) 2009 Google Inc. All rights reserved.
 * Copyright (C) 2007-2009 Torch Mobile, Inc.
 * Copyright (C) 2010 &yet, LLC. (nate@andyet.net)
 *
 * The Original Code is Mozilla Communicator client code, released
 * March 31, 1998.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998
 * the Initial Developer. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Alternatively, the contents of this file may be used under the terms
 * of either the Mozilla Public License Version 1.1, found at
 * http://www.mozilla.org/MPL/ (the "MPL") or the GNU General Public
 * License Version 2.0, found at http://www.fsf.org/copyleft/gpl.html
 * (the "GPL"), in which case the provisions of the MPL or the GPL are
 * applicable instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of one of those two
 * licenses (the MPL or the GPL) and not to allow others to use your
 * version of this file under the LGPL, indicate your decision by
 * deletingthe provisions above and replace them with the notice and
 * other provisions required by the MPL or the GPL, as the case may be.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under any of the LGPL, the MPL or the GPL.

 * Copyright 2006-2012 the V8 project authors. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of Google Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "JSDateMath.h"

#include "ExceptionHelpers.h"
#include "ISO8601.h"
#include "IntlObject.h"
#include "VM.h"
#include <limits>
#include <wtf/DateMath.h>
#include <wtf/Language.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/unicode/CharacterNames.h>
#include <wtf/unicode/icu/ICUHelpers.h>

#ifdef U_HIDE_DRAFT_API
#undef U_HIDE_DRAFT_API
#endif
#include <unicode/ucal.h>
#define U_HIDE_DRAFT_API 1

namespace JSC {
namespace JSDateMathInternal {
static constexpr bool verbose = false;

#if PLATFORM(DRIFTSTACK)
// G4 (tz-lang audit wponds5b1) — America/Asuncion DST host-leak override.
// macOS system ICU ships tzdata >=2024b, in which Paraguay's DST was abolished
// (America/Asuncion = permanent UTC-03:00). But every captured real iPhone still
// ships the OLDER bundled tzdata that OBSERVES Paraguay DST — verified byte-identical
// on iPhone 16 Pro/Safari 18.6 AND iPhone 17/Safari 26.5 (reference/realdevice-bs/
// tzoffset-iPhone_*): winter(Jul) = -03:00 (offsetMin 180), summer(Jan) = -04:00
// (offsetMin 240), transitions at 2026-03-22T03:00Z (DST->std) and 2026-10-04T04:00Z
// (std->DST). Without this override the fork would report no-DST for Asuncion = a
// per-session getTimezoneOffset()/DST host-leak for any America/Asuncion session.
//
// The historical (pre-abolition) Paraguay rule, which the bundled iOS tzdata applies:
//   DST (summer, UTC-04:00) from 1st Sunday of October 00:00 local to 4th Sunday of
//   March 00:00 local. Standard (UTC-03:00) otherwise. Transitions occur at 00:00 in
//   the NEW offset frame (Oct -> 04:00Z, Mar -> 03:00Z), matching the captured GTs.
// Returns the DST component in milliseconds (0 or -3600000) to ADD to the -03:00 raw
// offset; the caller folds it into rawOffset+dstOffset and the !!dstOffset DST flag.
//
// NOTE: this is band-INVARIANT across all currently captured iOS bands (18.6 + 26.5
// both observe it). If a future iOS adopts the upstream abolition it will need a band
// gate; until a capture shows that, the override applies on every archetype (matching
// the only real-device truth we have). Returns INT32_MIN to signal "not Asuncion".
static constexpr int32_t kAsuncionStdOffsetMs = -10800000; // -03:00
static int32_t driftstackAsuncionDstOffsetMs(double millisecondsFromEpoch)
{
    constexpr int64_t kMsPerDay = 86400000LL;
    constexpr int64_t kHourMs = 3600000LL;
    auto daysFromCivil = [](int y, unsigned m, unsigned d) -> int64_t {
        y -= m <= 2;
        int64_t era = (y >= 0 ? y : y - 399) / 400;
        unsigned yoe = static_cast<unsigned>(y - era * 400);
        unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + static_cast<int64_t>(doe) - 719468;
    };
    auto utcMidnightMs = [&](int y, unsigned m, unsigned d) -> int64_t {
        return daysFromCivil(y, m, d) * kMsPerDay;
    };
    auto weekday = [&](int y, unsigned m, unsigned d) -> unsigned {
        int64_t z = daysFromCivil(y, m, d);
        return static_cast<unsigned>(z >= -4 ? (z + 4) % 7 : (z + 5) % 7 + 6);
    };
    auto nthSunday = [&](int y, unsigned m, unsigned n) -> unsigned {
        unsigned wd = weekday(y, m, 1);
        unsigned firstSun = (wd == 0) ? 1 : (1 + (7 - wd));
        return firstSun + (n - 1) * 7;
    };

    int64_t utcMs = static_cast<int64_t>(millisecondsFromEpoch);
    // Resolve the Gregorian year of this UTC instant.
    int y = 1970 + static_cast<int>(utcMs / (static_cast<int64_t>(365.2425 * kMsPerDay)));
    while (utcMidnightMs(y, 1, 1) > utcMs)
        --y;
    while (utcMidnightMs(y + 1, 1, 1) <= utcMs)
        ++y;

    // DST starts 1st Sun Oct at 00:00 local DST(-04:00): UTC = localMidnight + 04:00.
    int64_t startUTC = utcMidnightMs(y, 10, nthSunday(y, 10, 1)) - (kAsuncionStdOffsetMs - kHourMs);
    // DST ends 4th Sun Mar at 00:00 local STD(-03:00): UTC = localMidnight + 03:00.
    int64_t endUTC = utcMidnightMs(y, 3, nthSunday(y, 3, 4)) - kAsuncionStdOffsetMs;

    // Southern-hemisphere summer wraps the year boundary: DST is active at/after the
    // October start (through year end) OR before the March end (from the prior October).
    if (utcMs >= startUTC || utcMs < endUTC)
        return -static_cast<int32_t>(kHourMs);
    return 0;
}
#endif
}

#if PLATFORM(COCOA)
std::atomic<uint64_t> lastTimeZoneID { 1 };
#endif

class OpaqueICUTimeZone {
    WTF_MAKE_TZONE_ALLOCATED(OpaqueICUTimeZone);
public:
    std::unique_ptr<UCalendar, ICUDeleter<ucal_close>> m_calendar;
    TimeZone m_canonicalTimeZone;
};

WTF_MAKE_TZONE_ALLOCATED_IMPL(OpaqueICUTimeZone);

void OpaqueICUTimeZoneDeleter::operator()(OpaqueICUTimeZone* timeZone)
{
    if (timeZone)
        delete timeZone;
}

// Get the combined UTC + DST offset for the time passed in.
//
// NOTE: The implementation relies on the fact that no time zones have
// more than one daylight savings offset change per month.
// If this function is called with NaN it returns random value.
LocalTimeOffset DateCache::calculateLocalTimeOffset(double millisecondsFromEpoch, TimeType inputTimeType)
{
    int32_t rawOffset = 0;
    int32_t dstOffset = 0;
    UErrorCode status = U_ZERO_ERROR;

    // This function can fail input date is invalid: NaN etc.
    // We can return any values in this case since later we fail when computing non timezone offset part anyway.
    constexpr LocalTimeOffset failed { false, 0 };

    auto& timeZoneCache = *this->timeZoneCache();
    ucal_setMillis(timeZoneCache.m_calendar.get(), millisecondsFromEpoch, &status);
    if (U_FAILURE(status))
        return failed;

    if (inputTimeType != TimeType::LocalTime) {
        rawOffset = ucal_get(timeZoneCache.m_calendar.get(), UCAL_ZONE_OFFSET, &status);
        if (U_FAILURE(status))
            return failed;
        dstOffset = ucal_get(timeZoneCache.m_calendar.get(), UCAL_DST_OFFSET, &status);
        if (U_FAILURE(status))
            return failed;
    } else {
        ucal_getTimeZoneOffsetFromLocal(timeZoneCache.m_calendar.get(), UCAL_TZ_LOCAL_FORMER, UCAL_TZ_LOCAL_FORMER, &rawOffset, &dstOffset, &status);
        if (U_FAILURE(status))
            return failed;
    }

#if PLATFORM(DRIFTSTACK)
    // G4 (tz-lang audit wponds5b1): override America/Asuncion DST to match the bundled
    // iOS tzdata (which still observes Paraguay DST) — macOS system ICU dropped it.
    // See driftstackAsuncionDstOffsetMs(). Only Asuncion is host-divergent in the
    // captured set (Almaty/Apia/Cairo/Gaza/Santiago/London all match host ICU).
    if (timeZoneCache.m_canonicalTimeZone.isID()) {
        const String& iana = intlTimeZoneIDToString(timeZoneCache.m_canonicalTimeZone.id());
        if (iana == "America/Asuncion"_s) {
            // Asuncion raw (standard) offset is -03:00 on both host ICU and iOS; only the
            // DST component differs. For UTC-instant input we recompute the DST window
            // directly from the historical Paraguay rule. (LocalTime input is rare here —
            // getTimezoneOffset() / Date display always take the UTC-instant branch — but
            // we apply the same rule for coherence; the standard offset is unchanged so the
            // local-wall instant maps to the same window save the ~1h transition seam.)
            int32_t iosDstMs = JSDateMathInternal::driftstackAsuncionDstOffsetMs(millisecondsFromEpoch);
            int32_t iosTotal = JSDateMathInternal::kAsuncionStdOffsetMs + iosDstMs;
            return { !!iosDstMs, iosTotal };
        }
    }
#endif

    return { !!dstOffset, rawOffset + dstOffset };
}

LocalTimeOffsetCache* DateCache::DSTCache::leastRecentlyUsed(LocalTimeOffsetCache* exclude)
{
    LocalTimeOffsetCache* result = nullptr;
    for (auto& cache : m_entries) {
        if (&cache == exclude)
            continue;
        if (!result) {
            result = &cache;
            continue;
        }
        if (result->epoch > cache.epoch)
            result = &cache;
    }
    *result = LocalTimeOffsetCache { };
    return result;
}

std::tuple<LocalTimeOffsetCache*, LocalTimeOffsetCache*> DateCache::DSTCache::probe(int64_t millisecondsFromEpoch)
{
    LocalTimeOffsetCache* before = nullptr;
    LocalTimeOffsetCache* after = nullptr;
    for (auto& cache : m_entries) {
        if (cache.start <= millisecondsFromEpoch) {
            if (!before || before->start < cache.start)
                before = &cache;
        } else if (millisecondsFromEpoch < cache.end) {
            if (!after || after->end > cache.end)
                after = &cache;
        }
    }

    if (!before) {
        if (m_before->isEmpty())
            before = m_before;
        else
            before = leastRecentlyUsed(after);
    }
    if (!after) {
        if (m_after->isEmpty() && before != m_after)
            after = m_after;
        else
            after = leastRecentlyUsed(before);
    }

    m_before = before;
    m_after = after;
    return std::tuple { before, after };
}

void DateCache::DSTCache::extendTheAfterCache(int64_t millisecondsFromEpoch, LocalTimeOffset offset)
{
    if (m_after->offset == offset && m_after->start - defaultDSTDeltaInMilliseconds <= millisecondsFromEpoch && millisecondsFromEpoch <= m_after->end) {
        // Extend the m_after cache.
        m_after->start = millisecondsFromEpoch;
        dataLogLnIf(JSDateMathInternal::verbose, "Cache extended1 from ", millisecondsFromEpoch, " to ", m_after->end, " ", offset.offset, " ", offset.isDST);
    } else {
        // The m_after cache is either invalid or starts too late.
        if (!m_after->isEmpty()) {
            // If the m_after cache is valid, replace it with a new cache.
            m_after = leastRecentlyUsed(m_before);
        }
        m_after->start = millisecondsFromEpoch;
        m_after->end = millisecondsFromEpoch;
        m_after->offset = offset;
        m_after->epoch = bumpEpoch();
        dataLogLnIf(JSDateMathInternal::verbose, "Cache miss, recompute2 ", millisecondsFromEpoch, " ", offset.offset, " ", offset.isDST);
    }
}

LocalTimeOffset DateCache::DSTCache::localTimeOffset(DateCache& dateCache, int64_t millisecondsFromEpoch, TimeType inputTimeType)
{
    if (millisecondsFromEpoch >= WTF::Int64Milliseconds::minECMAScriptTime && millisecondsFromEpoch <= WTF::Int64Milliseconds::maxECMAScriptTime) {
        // Do nothing. Use millisecondsFromEpoch directly
    } else {
        // Adjust to equivalent time.
        int64_t newTime = WTF::equivalentTime(millisecondsFromEpoch);
        dataLogLnIf(JSDateMathInternal::verbose, "Equivalent time conversion from ", millisecondsFromEpoch, " to ", newTime);
        millisecondsFromEpoch = newTime;
    }

    if (m_epoch > UINT32_MAX) [[unlikely]] {
        dataLogLnIf(JSDateMathInternal::verbose, "reset DSTCache");
        reset();
    }

    // If the time fits in the cached interval in the last cache hit, return the cached offset.
    if (m_before->start <= millisecondsFromEpoch && millisecondsFromEpoch <= m_before->end) {
        dataLogLnIf(JSDateMathInternal::verbose, "Previous Cache Hit");
        m_before->epoch = bumpEpoch();
        return m_before->offset;
    }

    probe(millisecondsFromEpoch);

    ASSERT(m_before->isEmpty() || m_before->start <= millisecondsFromEpoch);
    ASSERT(m_after->isEmpty() || millisecondsFromEpoch < m_after->start);

    if (m_before->isEmpty()) {
        // Cache miss!
        // Compute the DST offset for the time and shrink the cache interval
        // to only contain the time. This allows fast repeated DST offset
        // computations for the same time.
        LocalTimeOffset offset = dateCache.calculateLocalTimeOffset(millisecondsFromEpoch, inputTimeType);
        m_before->offset = offset;
        m_before->start = millisecondsFromEpoch;
        m_before->end = millisecondsFromEpoch;
        m_before->epoch = bumpEpoch();
        dataLogLnIf(JSDateMathInternal::verbose, "Cache miss, recompute1 ", millisecondsFromEpoch, " ", offset.offset, " ", offset.isDST);
        return offset;
    }

    // Cache hit!
    // If the time fits in the cached interval, return the cached offset.
    if (millisecondsFromEpoch <= m_before->end) {
        dataLogLnIf(JSDateMathInternal::verbose, "Cache hit, simple ", millisecondsFromEpoch, " ", m_before->offset.offset, " ", m_before->offset.isDST);
        m_before->epoch = bumpEpoch();
        return m_before->offset;
    }

    if ((millisecondsFromEpoch - defaultDSTDeltaInMilliseconds) > m_before->end) {
        LocalTimeOffset offset = dateCache.calculateLocalTimeOffset(millisecondsFromEpoch, inputTimeType);
        extendTheAfterCache(millisecondsFromEpoch, offset);
        std::swap(m_before, m_after);
        dataLogLnIf(JSDateMathInternal::verbose, "Cache hit, extend ", millisecondsFromEpoch, " ", offset.offset, " ", offset.isDST);
        return offset;
    }

    m_before->epoch = bumpEpoch();

    // Check if m_after is invalid or starts too late.
    // Note that start of invalid caches is maxECMAScriptTime.
    int64_t newAfterStart = m_before->end < WTF::Int64Milliseconds::maxECMAScriptTime - defaultDSTDeltaInMilliseconds ? m_before->end + defaultDSTDeltaInMilliseconds : WTF::Int64Milliseconds::maxECMAScriptTime;
    if (newAfterStart <= m_after->start) {
        LocalTimeOffset offset = dateCache.calculateLocalTimeOffset(newAfterStart, inputTimeType);
        extendTheAfterCache(newAfterStart, offset);
    } else {
        // Update the usage counter of m_after since it is going to be used.
        ASSERT(!m_after->isEmpty());
        m_after->epoch = bumpEpoch();
    }

    // Now the millisecondsFromEpoch is between m_before->end and m_after->start.
    // Only one daylight savings offset change can occur in this interval.

    if (m_before->offset == m_after->offset) {
        // Merge two caches if they have the same offset.
        m_before->end = m_after->end;
        *m_after = LocalTimeOffsetCache { };
        return m_before->offset;
    }

    // Binary search for daylight savings offset change point,
    // but give up if we don't find it in five iterations.
    for (int i = 4; i >= 0; --i) {
        int64_t delta = m_after->start - m_before->end;
        int64_t middle = !i ? millisecondsFromEpoch : m_before->end + delta / 2;
        LocalTimeOffset offset = dateCache.calculateLocalTimeOffset(middle, inputTimeType);
        if (m_before->offset == offset) {
            m_before->end = middle;
            dataLogLnIf(JSDateMathInternal::verbose, "Cache extended2 from ", m_before->start , " to ", m_before->end, " ", offset.offset, " ", offset.isDST);
            if (millisecondsFromEpoch <= m_before->end)
                return offset;
        } else {
            ASSERT(m_after->offset == offset);
            m_after->start = middle;
            dataLogLnIf(JSDateMathInternal::verbose, "Cache extended3 from ", m_after->start , " to ", m_after->end, " ", offset.offset, " ", offset.isDST);
            if (millisecondsFromEpoch >= m_after->start) {
                // This swap helps the optimistic fast check in subsequent invocations.
                std::swap(m_before, m_after);
                return offset;
            }
        }
    }

    return { };
}

double DateCache::gregorianDateTimeToMS(const GregorianDateTime& t, double milliseconds, TimeType inputTimeType)
{
    double day = dateToDaysFrom1970(t.year(), t.month(), t.monthDay());
    double ms = timeToMS(t.hour(), t.minute(), t.second(), milliseconds);
    double localTimeResult = (day * WTF::msPerDay) + ms;

    if (inputTimeType == TimeType::LocalTime && std::isfinite(localTimeResult))
        return localTimeResult - localTimeOffset(static_cast<int64_t>(localTimeResult), inputTimeType).offset;
    return localTimeResult;
}

double DateCache::localTimeToMS(double milliseconds, TimeType inputTimeType)
{
    if (inputTimeType == TimeType::LocalTime && std::isfinite(milliseconds))
        return milliseconds - localTimeOffset(static_cast<int64_t>(milliseconds), inputTimeType).offset;
    return milliseconds;
}

std::tuple<int32_t, int32_t, int32_t> DateCache::yearMonthDayFromDaysWithCache(int32_t days)
{
    if (m_yearMonthDayCache) {
        // Check conservatively if the given 'days' has
        // the same year and month as the cached 'days'.
        int32_t cachedDays = m_yearMonthDayCache->m_days;
        int32_t newDay = m_yearMonthDayCache->m_day + (days - cachedDays);
        if (newDay >= 1 && newDay <= 28) {
            int32_t year = m_yearMonthDayCache->m_year;
            int32_t month = m_yearMonthDayCache->m_month;
            m_yearMonthDayCache = { days, year, month, newDay };
            return std::tuple { year, month, newDay };
        }
    }
    auto [ year, month, day ] = WTF::yearMonthDayFromDays(days);
    m_yearMonthDayCache = { days, year, month, day };
    return std::tuple { year, month, day };
}

// input is UTC
void DateCache::msToGregorianDateTime(double millisecondsFromEpoch, TimeType outputTimeType, GregorianDateTime& tm)
{
    LocalTimeOffset localTime;
    if (outputTimeType == TimeType::LocalTime && std::isfinite(millisecondsFromEpoch)) {
        localTime = localTimeOffset(static_cast<int64_t>(millisecondsFromEpoch));
        millisecondsFromEpoch += localTime.offset;
    }
    if (std::isfinite(millisecondsFromEpoch)) {
        WTF::Int64Milliseconds timeClipped(static_cast<int64_t>(millisecondsFromEpoch));
        int32_t days = WTF::msToDays(timeClipped);
        int32_t timeInDayMS = WTF::timeInDay(timeClipped, days);
        auto [year, month, day] = yearMonthDayFromDaysWithCache(days);
        int32_t hour = timeInDayMS / (60 * 60 * 1000);
        int32_t minute = (timeInDayMS / (60 * 1000)) % 60;
        int32_t second = (timeInDayMS / 1000) % 60;
        tm = GregorianDateTime(year, month, dayInYear(year, month, day), day, WTF::weekDay(days), hour, minute, second, localTime.offset / WTF::Int64Milliseconds::msPerMinute, localTime.isDST);
    } else
        tm = GregorianDateTime(millisecondsFromEpoch, localTime);
}

double DateCache::parseDate(JSGlobalObject* globalObject, VM& vm, const String& date)
{
    auto scope = DECLARE_THROW_SCOPE(vm);

    if (date == m_cachedDateString)
        return m_cachedDateStringValue;

    // After ICU 72, CLDR generates narrowNoBreakSpace for date time format. Thus, `new Date().toLocaleString('en-US')` starts generating
    // a string including narrowNoBreakSpaces instead of simple spaces. However since code in the wild assumes `new Date(new Date().toLocaleString('en-US'))`
    // works, we need to maintain the ability to parse string including narrowNoBreakSpaces. Rough consensus among implementaters is replacing narrowNoBreakSpaces
    // with simple spaces before parsing.
    String updatedString = makeStringByReplacingAll(date, narrowNoBreakSpace, space);

    auto expectedString = updatedString.tryGetUTF8();
    if (!expectedString) {
        if (expectedString.error() == UTF8ConversionError::OutOfMemory)
            throwOutOfMemoryError(globalObject, scope);
        // https://tc39.github.io/ecma262/#sec-date-objects section 20.3.3.2 states that:
        // "Unrecognizable Strings or dates containing illegal element values in the
        // format String shall cause Date.parse to return NaN."
        return std::numeric_limits<double>::quiet_NaN();
    }

    auto parseDateImpl = [this] (auto dateString) {
        bool isLocalTime;
        double value = WTF::parseES5Date(dateString, isLocalTime);
        if (std::isnan(value))
            value = WTF::parseDate(dateString, isLocalTime);

        if (isLocalTime && std::isfinite(value))
            value -= localTimeOffset(static_cast<int64_t>(value), TimeType::LocalTime).offset;

        return value;
    };

    // FIXME: expectedString is UTF-8 but parseDateImpl requires Latin1. Which is correct?
    double value = parseDateImpl(byteCast<Latin1Character>(expectedString.value().span()));
    m_cachedDateString = date;
    m_cachedDateStringValue = value;
    return value;
}

// https://tc39.es/ecma402/#sec-defaulttimezone
TimeZone DateCache::defaultTimeZone()
{
    return timeZoneCache()->m_canonicalTimeZone;
}

String DateCache::timeZoneDisplayName(bool isDST)
{
    if (m_timeZoneStandardDisplayNameCache.isNull()) {
        auto& timeZoneCache = *this->timeZoneCache();
#if PLATFORM(DRIFTSTACK)
        // wave-c-3: iPhone Safari (iOS 26.4) returns specific localized
        // standard/DST names for top timezones (e.g., 'Türkiye Standard
        // Time' for Europe/Istanbul). Mac's bundled ICU CLDR data lacks
        // many of these names regardless of locale, so ucal_getTimeZoneDisplayName
        // falls back to 'GMT+offset' format (V-074 finding). Maintain a
        // per-TZ localized-name lookup table on Driftstack; if the TZ
        // is in the table return the iPhone string, else fall through
        // to ICU.
        //
        // Table is sourced empirically from iPhone reference captures.
        // Extensible: add entries as more iPhone-archetype timezones are
        // observed in customer sessions or rig captures. For TZs not in
        // the table, ICU's fallback is correct enough that the diff
        // is an unknown-unknown rather than a known-wrong.
        // Display-name entries can contain non-ASCII (e.g. "Türkiye"); use
        // UTF-8 char* and convert via String::fromUTF8 at lookup time so
        // multi-byte sequences land as Unicode rather than Latin1-mojibake.
        //
        // PER-SAFARI-VERSION GATING (the CLDR-version bands): the iOS CLDR data version ships per
        // Safari release, so the en-US LONG display name for these zones FLIPS across version bands.
        // The override therefore carries BOTH the OLD-CLDR name (pre-26.4) and the NEW-CLDR name
        // (>=26.4); the band selector below picks the one the archetype's Safari version really
        // returns. Bands are characterized from real-device BrowserStack GTs (NOT the booted sim,
        // whose ICU lags — the Asia/Anadyr / Asia/Kamchatka split lesson):
        //   - Safari <26.4  (verified 18.6 iPhone_16_Pro/Plus; 26.2 iPhone_14): OLD-CLDR metropolitan
        //     names (Lagos/Kinshasa="West Africa Standard Time", Taipei="Taipei Standard Time",
        //     Kamchatka="Petropavlovsk-Kamchatski Standard Time", Apia="Apia Standard Time", ...).
        //   - Safari >=26.4 (verified 26.4 iPhone_17/14/15PM; 27.0 iPhone_16PM): NEW-CLDR metropolitan
        //     names (Lagos="West Africa Time", Taipei="Taiwan Standard Time", Kamchatka="Kamchatka
        //     Standard Time", Apia="Samoa Standard Time", ...) — the current launch (#106) values.
        // GMT/Etc/GMT oscillate INDEPENDENTLY of the metropolitan flip and are handled separately
        // below: 18.6="Coordinated Universal Time", 26.0-26.x="Greenwich Mean Time", 27.0 reverts to
        // "Coordinated Universal Time" (real-device GTs).
        //
        // newName==oldName for a zone where iOS never changed it (Anadyr, Honolulu) — invariant rows.
        // An empty oldName/newName ("") means: serve NO override in that band (fall through to macOS
        // ICU). Used for Istanbul on pre-26.4, where the real device returns a bare "GMT+03:00" that
        // the macOS ICU fallback already produces.
        struct TZDisplayName { ASCIILiteral canonical; const char* oldName; const char* newName; };
        // COMPLETE iOS-vs-macOS ICU timezone-display-name divergence table (prod-ready: ALL zones, not
        // a hardcoded few). Built from the iOS-26.5 simulator (== real iPhone) vs the fork's macOS ICU
        // across all 448 IANA zones (alltz probe, fp-divergence-sweep 2026-06-21) for the NEW-CLDR
        // names, and from the real-device tzResolve GTs for the OLD-CLDR names. Zones NOT listed
        // already match macOS ICU → handled by the ucal fallback below.
        static constexpr TZDisplayName iPhoneTZDisplayNames[] = {
            // West Africa: OLD "West Africa Standard Time" → NEW "West Africa Time"
            { "Africa/Bangui"_s,        "West Africa Standard Time", "West Africa Time" },
            { "Africa/Brazzaville"_s,   "West Africa Standard Time", "West Africa Time" },
            { "Africa/Douala"_s,        "West Africa Standard Time", "West Africa Time" },
            { "Africa/Kinshasa"_s,      "West Africa Standard Time", "West Africa Time" },
            { "Africa/Lagos"_s,         "West Africa Standard Time", "West Africa Time" },
            { "Africa/Libreville"_s,    "West Africa Standard Time", "West Africa Time" },
            { "Africa/Luanda"_s,        "West Africa Standard Time", "West Africa Time" },
            { "Africa/Malabo"_s,        "West Africa Standard Time", "West Africa Time" },
            { "Africa/Ndjamena"_s,      "West Africa Standard Time", "West Africa Time" },
            { "Africa/Niamey"_s,        "West Africa Standard Time", "West Africa Time" },
            { "Africa/Porto-Novo"_s,    "West Africa Standard Time", "West Africa Time" },
            // OLD: "Dumont-d’Urville Time" (ASCII hyphen) → NEW: "Dumont d’Urville Time" (space). Both U+2019.
            { "Antarctica/DumontDUrville"_s, "Dumont-d\xE2\x80\x99Urville Time", "Dumont d\xE2\x80\x99Urville Time" },
            // Asia/Anadyr: INVARIANT "Anadyr Standard Time" across all bands (real-device GT 18.6/26.2/
            // 26.4/27.0 all agree). A DISTINCT metazone from Kamchatka on iOS; macOS ICU collapses it.
            { "Asia/Anadyr"_s,          "Anadyr Standard Time", "Anadyr Standard Time" },
            { "Asia/Brunei"_s,          "Brunei Darussalam Time", "Brunei Time" },
            { "Asia/Dili"_s,            "East Timor Time", "Timor-Leste Time" },
            { "Asia/Hovd"_s,            "Hovd Standard Time", "Khovd Standard Time" },
            { "Asia/Kamchatka"_s,       "Petropavlovsk-Kamchatski Standard Time", "Kamchatka Standard Time" },
            { "Asia/Taipei"_s,          "Taipei Standard Time", "Taiwan Standard Time" },
            { "Pacific/Apia"_s,         "Apia Standard Time", "Samoa Standard Time" },
            // Pacific/Honolulu: INVARIANT "Hawaii-Aleutian Standard Time" (macOS: bare "GMT-10:00").
            { "Pacific/Honolulu"_s,     "Hawaii-Aleutian Standard Time", "Hawaii-Aleutian Standard Time" },
            { "Pacific/Midway"_s,       "Samoa Standard Time", "American Samoa Standard Time" },
            { "Pacific/Pago_Pago"_s,    "Samoa Standard Time", "American Samoa Standard Time" },
            { "Pacific/Ponape"_s,       "Ponape Time", "Pohnpei Time" },
            // Türkiye: OLD = explicit "GMT+03:00" — macOS ICU's new CLDR WRONGLY produces "Türkiye
            // Standard Time" pre-26.4, so serve the offset explicitly (real 26.3 GT = "GMT+03:00";
            // verified wl6mgnqcy). NEW = "Türkiye Standard Time". Asia/Istanbul = alias of Europe/Istanbul.
            { "Europe/Istanbul"_s,      "GMT+03:00", "T\xC3\xBCrkiye Standard Time" },
            { "Asia/Istanbul"_s,        "GMT+03:00", "T\xC3\xBCrkiye Standard Time" },
        };
        // Archetype Safari version (from DRIFTSTACK_ARCHETYPE "safariNN_M" token; e.g. "safari26_4").
        // Parse major and minor (underscore-separated). 0/0 if unset → defaults to the NEW-CLDR band
        // (preserves the current launch behaviour when the env var is absent).
        int dsSafariMajor = 0;
        int dsSafariMinor = 0;
        if (const char* dsArch = getenv("DRIFTSTACK_ARCHETYPE")) {
            std::string_view sv { dsArch };
            auto pos = sv.find("safari");
            if (pos != std::string_view::npos) {
                sv.remove_prefix(pos + 6);
                size_t i = 0;
                for (; i < sv.size() && sv[i] >= '0' && sv[i] <= '9'; ++i)
                    dsSafariMajor = dsSafariMajor * 10 + (sv[i] - '0');
                if (i < sv.size() && sv[i] == '_') {
                    ++i;
                    for (; i < sv.size() && sv[i] >= '0' && sv[i] <= '9'; ++i)
                        dsSafariMinor = dsSafariMinor * 10 + (sv[i] - '0');
                }
            }
        }
        // NEW-CLDR metropolitan band: Safari >= 26.4 (major>26, or 26.x with minor>=4). Unset (0.0)
        // → NEW (launch default). Below 26.4 (incl 18.6 and 26.0-26.2) → OLD-CLDR.
        bool dsNewCLDR = dsSafariMajor == 0
            || dsSafariMajor > 26
            || (dsSafariMajor == 26 && dsSafariMinor >= 4);
        // GMT/Etc/GMT name oscillation (independent of the metropolitan flip): "Greenwich Mean Time"
        // on Safari 26.0-26.x; "Coordinated Universal Time" on 18.6 (<26) and on 27.0+ (revert).
        // Unset (0.0) → "Greenwich Mean Time" (launch 26.4 default).
        const char* dsGmtName = (dsSafariMajor == 0 || (dsSafariMajor == 26))
            ? "Greenwich Mean Time"
            : "Coordinated Universal Time";
        String canonicalString = timeZoneCache.m_canonicalTimeZone.toICUString();
        StringView canonicalView(canonicalString);
        // GMT / Etc/GMT: band-selected (oscillates CUT→GMT→CUT).
        if (canonicalView == "GMT"_s || canonicalView == "Etc/GMT"_s) {
            m_timeZoneStandardDisplayNameCache = String::fromLatin1(dsGmtName);
            m_timeZoneDSTDisplayNameCache = m_timeZoneStandardDisplayNameCache;
            return m_timeZoneStandardDisplayNameCache;
        }
        // UTC / Etc/UTC — Date.toString() parenthetical ONLY: "Greenwich Mean Time" on Safari <27 (real
        // iPhone GT-confirmed 18.6 + 26.4: "GMT+0000 (Greenwich Mean Time)"), "Coordinated Universal Time"
        // on >=27. ASYMMETRIC vs the Intl long name (which is "Coordinated Universal Time" on every band —
        // handled in IntlDateTimeFormat.cpp, left unchanged). macOS ICU wrongly returns CUT here on every
        // band → host-leak on the default-UTC config (launch 26.4 included). Unset (major 0) → Greenwich.
        if (canonicalView == "UTC"_s || canonicalView == "Etc/UTC"_s) {
            m_timeZoneStandardDisplayNameCache = String::fromLatin1(dsSafariMajor < 27 ? "Greenwich Mean Time" : "Coordinated Universal Time");
            m_timeZoneDSTDisplayNameCache = m_timeZoneStandardDisplayNameCache;
            return m_timeZoneStandardDisplayNameCache;
        }
        for (const auto& entry : iPhoneTZDisplayNames) {
            if (canonicalView != StringView(entry.canonical))
                continue;
            const char* name = dsNewCLDR ? entry.newName : entry.oldName;
            if (!name[0]) // empty band value → fall through to macOS ICU (e.g. Istanbul pre-26.4)
                break;
            m_timeZoneStandardDisplayNameCache = String::fromUTF8(name);
            m_timeZoneDSTDisplayNameCache = m_timeZoneStandardDisplayNameCache;
            if (isDST)
                return m_timeZoneDSTDisplayNameCache;
            return m_timeZoneStandardDisplayNameCache;
        }
        CString language { "en_US" };
#else
        CString language = defaultLanguage().utf8();
#endif
        {
            Vector<char16_t, 32> standardDisplayNameBuffer;
            auto status = callBufferProducingFunction(ucal_getTimeZoneDisplayName, timeZoneCache.m_calendar.get(), UCAL_STANDARD, language.data(), standardDisplayNameBuffer);
            if (U_SUCCESS(status))
                m_timeZoneStandardDisplayNameCache = String::adopt(WTF::move(standardDisplayNameBuffer));
        }
        {
            Vector<char16_t, 32> dstDisplayNameBuffer;
            auto status = callBufferProducingFunction(ucal_getTimeZoneDisplayName, timeZoneCache.m_calendar.get(), UCAL_DST, language.data(), dstDisplayNameBuffer);
            if (U_SUCCESS(status))
                m_timeZoneDSTDisplayNameCache = String::adopt(WTF::move(dstDisplayNameBuffer));
        }
    }
    if (isDST)
        return m_timeZoneDSTDisplayNameCache;
    return m_timeZoneStandardDisplayNameCache;
}

static Lock timeZoneCacheLock;

#if PLATFORM(COCOA)
static void timeZoneChangeNotification(CFNotificationCenterRef, void*, CFStringRef, const void*, CFDictionaryRef)
{
    Locker locker { timeZoneCacheLock };
    ASSERT(isMainThread());
    ++lastTimeZoneID;
}
#endif

// To confine icu::TimeZone destructor invocation in this file.
DateCache::DateCache()
{
#if PLATFORM(COCOA)
    static std::once_flag onceKey;
    std::call_once(onceKey, [&] {
        CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), nullptr, timeZoneChangeNotification, kCFTimeZoneSystemTimeZoneDidChangeNotification, nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);
    });
#endif
}

static TimeZone retrieveTimeZoneInformation()
{
    Locker locker { timeZoneCacheLock };
    static NeverDestroyed<std::tuple<TimeZone, uint64_t>> globalCache;

    bool isCacheStale = true;
    uint64_t currentID = 0;
#if PLATFORM(COCOA)
    currentID = lastTimeZoneID.load();
    isCacheStale = std::get<1>(globalCache.get()) != currentID;
#endif
    if (isCacheStale) {
        Vector<char16_t, 32> timeZoneID;
        getTimeZoneOverride(timeZoneID);
        TimeZone canonical;
        UErrorCode status = U_ZERO_ERROR;
        if (timeZoneID.isEmpty()) {
            status = callBufferProducingFunction(ucal_getHostTimeZone, timeZoneID);
            ASSERT_UNUSED(status, U_SUCCESS(status));
        }
        if (U_SUCCESS(status)) {
            // Resolve through intlResolveTimeZoneID so the host TZ collapses onto its IANA
            // primary identifier (e.g. "Asia/Calcutta" -> "Asia/Kolkata") and UTC-equivalent
            // names map to the UTC TimeZoneID.
            String primary = toPrimaryIanaTimeZoneIdentifier(timeZoneID.span());
            if (auto id = intlResolveTimeZoneID(primary))
                canonical = TimeZone::fromID(id.value());
        }

        globalCache.get() = std::tuple { canonical, currentID };
    }
    return std::get<0>(globalCache.get());
}

DateCache::~DateCache() = default;

Ref<DateInstanceData> DateCache::cachedDateInstanceData(double millisecondsFromEpoch)
{
    return *m_dateInstanceCache.add(millisecondsFromEpoch);
}

void DateCache::timeZoneCacheSlow()
{
    ASSERT(!m_timeZoneCache);
    TimeZone canonical = retrieveTimeZoneInformation();
    String timeZoneForICU = canonical.toICUString();
    StringView timeZoneView(timeZoneForICU);
    auto upconverted = timeZoneView.upconvertedCharacters();
    auto* cache = new OpaqueICUTimeZone;
    cache->m_canonicalTimeZone = canonical;
    UErrorCode status = U_ZERO_ERROR;
    cache->m_calendar = std::unique_ptr<UCalendar, ICUDeleter<ucal_close>>(ucal_open(upconverted, timeZoneView.length(), "", UCAL_DEFAULT, &status));
    ASSERT_UNUSED(status, U_SUCCESS(status));
    ucal_setGregorianChange(cache->m_calendar.get(), minECMAScriptTime, &status); // Ignore "unsupported" error.
    m_timeZoneCache = std::unique_ptr<OpaqueICUTimeZone, OpaqueICUTimeZoneDeleter>(cache);
}

void DateCache::resetIfNecessarySlow()
{
    // FIXME: We should clear it only when we know the timezone has been changed on Non-Cocoa platforms.
    // https://bugs.webkit.org/show_bug.cgi?id=218365
    m_timeZoneCache.reset();
    for (auto& cache : m_caches)
        cache.reset();
    m_yearMonthDayCache = std::nullopt;
    m_cachedDateString = String();
    m_cachedDateStringValue = std::numeric_limits<double>::quiet_NaN();
    m_dateInstanceCache.reset();
    m_timeZoneStandardDisplayNameCache = String();
    m_timeZoneDSTDisplayNameCache = String();
}

} // namespace JSC
