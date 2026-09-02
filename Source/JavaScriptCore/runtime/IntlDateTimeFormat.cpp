/*
 * Copyright (C) 2015 Andy VanWagoner (andy@vanwagoner.family)
 * Copyright (C) 2016-2025 Apple Inc. All rights reserved.
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
#include "IntlDateTimeFormat.h"

#include "ISO8601.h"
#include "IntlCache.h"
#include "IntlObjectInlines.h"
#include "IntlPartObject.h"
#include "JSBoundFunction.h"
#include "JSCInlines.h"
#include "JSDateMath.h"
#include "ObjectConstructor.h"
#include <unicode/ucal.h>
#include <unicode/uenum.h>
#include <wtf/Range.h>
#include <wtf/text/MakeString.h>
#include <wtf/text/StringBuilder.h>
#include <wtf/unicode/CharacterNames.h>
#include <wtf/unicode/icu/ICUHelpers.h>

#include <unicode/uformattedvalue.h>
#ifdef U_HIDE_DRAFT_API
#undef U_HIDE_DRAFT_API
#endif
#include <unicode/udateintervalformat.h>
#define U_HIDE_DRAFT_API 1

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace JSC {

// We do not use ICUDeleter<udtitvfmt_close> because we do not want to include udateintervalformat.h in IntlDateTimeFormat.h.
// udateintervalformat.h needs to be included with #undef U_HIDE_DRAFT_API, and we would like to minimize this effect in IntlDateTimeFormat.cpp.
void UDateIntervalFormatDeleter::operator()(UDateIntervalFormat* formatter)
{
    if (formatter)
        udtitvfmt_close(formatter);
}

const ClassInfo IntlDateTimeFormat::s_info = { "Object"_s, &Base::s_info, nullptr, nullptr, CREATE_METHOD_TABLE(IntlDateTimeFormat) };

// Approximate sizes of ICU objects for GC memory pressure reporting, measured empirically with udat_open + udat_format.
static constexpr size_t estimatedUDateFormatSize = 30000;
static constexpr size_t estimatedUDateIntervalFormatSize = 30000;

namespace IntlDateTimeFormatInternal {
static constexpr bool verbose = false;
}

IntlDateTimeFormat* IntlDateTimeFormat::create(VM& vm, Structure* structure)
{
    IntlDateTimeFormat* format = new (NotNull, allocateCell<IntlDateTimeFormat>(vm)) IntlDateTimeFormat(vm, structure);
    format->finishCreation(vm);
    return format;
}

Structure* IntlDateTimeFormat::createStructure(VM& vm, JSGlobalObject* globalObject, JSValue prototype)
{
    return Structure::create(vm, globalObject, prototype, TypeInfo(ObjectType, StructureFlags), info());
}

IntlDateTimeFormat::IntlDateTimeFormat(VM& vm, Structure* structure)
    : Base(vm, structure)
{
}

template<typename Visitor>
void IntlDateTimeFormat::visitChildrenImpl(JSCell* cell, Visitor& visitor)
{
    IntlDateTimeFormat* thisObject = uncheckedDowncast<IntlDateTimeFormat>(cell);
    ASSERT_GC_OBJECT_INHERITS(thisObject, info());

    Base::visitChildren(thisObject, visitor);

    visitor.append(thisObject->m_boundFormat);

    if (thisObject->m_dateFormat)
        visitor.reportExtraMemoryVisited(estimatedUDateFormatSize);
    if (thisObject->m_dateIntervalFormat)
        visitor.reportExtraMemoryVisited(estimatedUDateIntervalFormatSize);
}

DEFINE_VISIT_CHILDREN(IntlDateTimeFormat);

void IntlDateTimeFormat::setBoundFormat(VM& vm, JSBoundFunction* format)
{
    m_boundFormat.set(vm, this, format);
}

Vector<String> IntlDateTimeFormat::localeData(const String& locale, RelevantExtensionKey key)
{
    Vector<String> keyLocaleData;
    switch (key) {
    case RelevantExtensionKey::Ca: {
        UErrorCode status = U_ZERO_ERROR;
        auto calendars = std::unique_ptr<UEnumeration, ICUDeleter<uenum_close>>(ucal_getKeywordValuesForLocale("calendar", locale.utf8().data(), false, &status));
        ASSERT(U_SUCCESS(status));

        int32_t nameLength;
        while (const char* availableName = uenum_next(calendars.get(), &nameLength, &status)) {
            ASSERT(U_SUCCESS(status));
            String calendar = String(unsafeMakeSpan(availableName, static_cast<size_t>(nameLength)));
            // Adding "islamicc" candidate for backward compatibility.
            if (calendar == "islamic-civil"_s)
                keyLocaleData.append("islamicc"_s);

            if (auto mapped = mapICUCalendarKeywordToBCP47(calendar)) {
                // Specially allowing non BCP-47 compliant cases here, e.g. "gregorian"
                // This is fine because this function's purpose is collecting what calendar strings are accepted by IntlDateTimeFormat.
                // When "gregorian" is specified, we convert it to "gregory" to make it aligned to BCP-47. Thus we accept non BCP-47 compliant
                // calendar IDs only when we can convert it to corresponding BCP-47 compliant ID: when mapICUCalendarKeywordToBCP47 returns a mapped value.
                keyLocaleData.append(WTF::move(calendar));
                keyLocaleData.append(WTF::move(mapped.value()));
            } else {
                // Skip if the obtained calendar code is not meeting Unicode Locale Identifier's `type` definition
                // as whole ECMAScript's i18n is relying on Unicode Local Identifiers.
                if (isUnicodeLocaleIdentifierType(calendar))
                    keyLocaleData.append(WTF::move(calendar));
            }
        }
        break;
    }
    case RelevantExtensionKey::Hc:
        // Null default so we know to use 'j' in pattern.
        keyLocaleData.append(String());
        keyLocaleData.append("h11"_s);
        keyLocaleData.append("h12"_s);
        keyLocaleData.append("h23"_s);
        keyLocaleData.append("h24"_s);
        break;
    case RelevantExtensionKey::Nu:
        keyLocaleData = numberingSystemsForLocale(locale);
        break;
    default:
        ASSERT_NOT_REACHED();
    }
    return keyLocaleData;
}

template<typename Container>
static inline unsigned NODELETE skipLiteralText(const Container& container, unsigned start, unsigned length)
{
    // Skip literal text. We do not recognize '' single quote specially.
    // `'ICU''s change'` is `ICU's change` literal text, but even if we split this text into two literal texts,
    // we can anyway skip the same thing.
    // This function returns the last character index which can be considered as a literal text.
    ASSERT(length);
    ASSERT(start < length);
    ASSERT(container[start] == '\'');
    unsigned index = start;
    ++index;
    if (!(index < length))
        return length - 1;
    for (; index < length; ++index) {
        if (container[index] == '\'')
            return index;
    }
    return length - 1;
}

void IntlDateTimeFormat::setFormatsFromPattern(StringView pattern)
{
    // Get all symbols from the pattern, and set format fields accordingly.
    // http://unicode.org/reports/tr35/tr35-dates.html#Date_Field_Symbol_Table
    //
    // A date pattern is a character string consisting of two types of elements:
    // 1. Pattern fields, which repeat a specific pattern character one or more times.
    //    These fields are replaced with date and time data from a calendar when formatting,
    //    or used to generate data for a calendar when parsing. Currently, A..Z and a..z are
    //    reserved for use as pattern characters (unless they are quoted, see next item).
    //    The pattern characters currently defined, and the meaning of different fields
    //    lengths for then, are listed in the Date Field Symbol Table below.
    // 2. Literal text, which is output as-is when formatting, and must closely match when
    //    parsing. Literal text can include:
    //      1. Any characters other than A..Z and a..z, including spaces and punctuation.
    //      2. Any text between single vertical quotes ('xxxx'), which may include A..Z and
    //         a..z as literal text.
    //      3. Two adjacent single vertical quotes (''), which represent a literal single quote,
    //         either inside or outside quoted text.
    unsigned length = pattern.length();
    for (unsigned i = 0; i < length; ++i) {
        auto currentCharacter = pattern[i];

        if (currentCharacter == '\'') {
            i = skipLiteralText(pattern, i, length);
            continue;
        }

        if (!isASCIIAlpha(currentCharacter))
            continue;

        unsigned count = 1;
        while (i + 1 < length && pattern[i + 1] == currentCharacter) {
            ++count;
            ++i;
        }

        switch (currentCharacter) {
        case 'G':
            if (count <= 3)
                m_era = Era::Short;
            else if (count == 4)
                m_era = Era::Long;
            else if (count == 5)
                m_era = Era::Narrow;
            break;
        case 'y':
            if (count == 1)
                m_year = Year::Numeric;
            else if (count == 2)
                m_year = Year::TwoDigit;
            break;
        case 'M':
        case 'L':
            if (count == 1)
                m_month = Month::Numeric;
            else if (count == 2)
                m_month = Month::TwoDigit;
            else if (count == 3)
                m_month = Month::Short;
            else if (count == 4)
                m_month = Month::Long;
            else if (count == 5)
                m_month = Month::Narrow;
            break;
        case 'E':
        case 'e':
        case 'c':
            if (count <= 3)
                m_weekday = Weekday::Short;
            else if (count == 4)
                m_weekday = Weekday::Long;
            else if (count == 5)
                m_weekday = Weekday::Narrow;
            break;
        case 'd':
            if (count == 1)
                m_day = Day::Numeric;
            else if (count == 2)
                m_day = Day::TwoDigit;
            break;
        case 'a':
        case 'b':
        case 'B':
            if (count <= 3)
                m_dayPeriod = DayPeriod::Short;
            else if (count == 4)
                m_dayPeriod = DayPeriod::Long;
            else if (count == 5)
                m_dayPeriod = DayPeriod::Narrow;
            break;
        case 'h':
        case 'H':
        case 'k':
        case 'K': {
            // Populate hourCycle from actually generated patterns. It is possible that locale or option is specifying hourCycle explicitly,
            // but the generated pattern does not include related part since the pattern does not include hours.
            // This is tested in test262/test/intl402/DateTimeFormat/prototype/resolvedOptions/hourCycle-dateStyle.js and our stress tests.
            // Example:
            //     new Intl.DateTimeFormat(`de-u-hc-h11`, {
            //         dateStyle: "full"
            //     }).resolvedOptions().hourCycle === undefined
            m_hourCycle = hourCycleFromSymbol(currentCharacter);
            if (count == 1)
                m_hour = Hour::Numeric;
            else if (count == 2)
                m_hour = Hour::TwoDigit;
            break;
        }
        case 'm':
            if (count == 1)
                m_minute = Minute::Numeric;
            else if (count == 2)
                m_minute = Minute::TwoDigit;
            break;
        case 's':
            if (count == 1)
                m_second = Second::Numeric;
            else if (count == 2)
                m_second = Second::TwoDigit;
            break;
        case 'z':
            if (count == 1)
                m_timeZoneName = TimeZoneName::Short;
            else if (count == 4)
                m_timeZoneName = TimeZoneName::Long;
            break;
        case 'O':
            if (count == 1)
                m_timeZoneName = TimeZoneName::ShortOffset;
            else if (count == 4)
                m_timeZoneName = TimeZoneName::LongOffset;
            break;
        case 'v':
        case 'V':
            if (count == 1)
                m_timeZoneName = TimeZoneName::ShortGeneric;
            else if (count == 4)
                m_timeZoneName = TimeZoneName::LongGeneric;
            break;
        case 'S':
            m_fractionalSecondDigits = count;
            break;
        }
    }
}

IntlDateTimeFormat::HourCycle IntlDateTimeFormat::parseHourCycle(const String& hourCycle)
{
    if (hourCycle == "h11"_s)
        return HourCycle::H11;
    if (hourCycle == "h12"_s)
        return HourCycle::H12;
    if (hourCycle == "h23"_s)
        return HourCycle::H23;
    if (hourCycle == "h24"_s)
        return HourCycle::H24;
    return HourCycle::None;
}

inline IntlDateTimeFormat::HourCycle IntlDateTimeFormat::hourCycleFromSymbol(char16_t symbol)
{
    switch (symbol) {
    case 'K':
        return HourCycle::H11;
    case 'h':
        return HourCycle::H12;
    case 'H':
        return HourCycle::H23;
    case 'k':
        return HourCycle::H24;
    }
    return HourCycle::None;
}

IntlDateTimeFormat::HourCycle IntlDateTimeFormat::hourCycleFromPattern(const Vector<char16_t, 32>& pattern)
{
    for (unsigned i = 0, length = pattern.size(); i < length; ++i) {
        auto character = pattern[i];

        if (character == '\'') {
            i = skipLiteralText(pattern, i, length);
            continue;
        }

        switch (character) {
        case 'K':
        case 'h':
        case 'H':
        case 'k':
            return hourCycleFromSymbol(character);
        }
    }
    return HourCycle::None;
}

inline void IntlDateTimeFormat::replaceHourCycleInSkeleton(Vector<char16_t, 32>& skeleton, bool isHour12)
{
    char16_t skeletonCharacter = 'H';
    if (isHour12)
        skeletonCharacter = 'h';
    for (unsigned i = 0, length = skeleton.size(); i < length; ++i) {
        auto& character = skeleton[i];

        // ICU DateTimeFormat skeleton also has single-quoted literal text.
        // https://github.com/unicode-org/icu/blob/main/icu4c/source/i18n/dtptngen.cpp
        if (character == '\'') {
            i = skipLiteralText(skeleton, i, length);
            continue;
        }

        switch (character) {
        case 'h':
        case 'H':
        case 'j':
            character = skeletonCharacter;
            break;
        }
    }
}

inline void IntlDateTimeFormat::replaceHourCycleInPattern(Vector<char16_t, 32>& pattern, HourCycle hourCycle)
{
    char16_t hourFromHourCycle = 'H';
    switch (hourCycle) {
    case HourCycle::H11:
        hourFromHourCycle = 'K';
        break;
    case HourCycle::H12:
        hourFromHourCycle = 'h';
        break;
    case HourCycle::H23:
        hourFromHourCycle = 'H';
        break;
    case HourCycle::H24:
        hourFromHourCycle = 'k';
        break;
    case HourCycle::None:
        return;
    }

    for (unsigned i = 0, length = pattern.size(); i < length; ++i) {
        auto& character = pattern[i];

        if (character == '\'') {
            i = skipLiteralText(pattern, i, length);
            continue;
        }

        switch (character) {
        case 'K':
        case 'h':
        case 'H':
        case 'k':
            character = hourFromHourCycle;
            break;
        }
    }
}

String IntlDateTimeFormat::buildSkeleton(Weekday weekday, Era era, Year year, Month month, Day day, TriState hour12, HourCycle hourCycle, Hour hour, DayPeriod dayPeriod, Minute minute, Second second, unsigned fractionalSecondDigits, TimeZoneName timeZoneName)
{
    StringBuilder skeletonBuilder;

    switch (weekday) {
    case Weekday::Narrow:
        skeletonBuilder.append("EEEEE"_s);
        break;
    case Weekday::Short:
        skeletonBuilder.append("EEE"_s);
        break;
    case Weekday::Long:
        skeletonBuilder.append("EEEE"_s);
        break;
    case Weekday::None:
        break;
    }

    switch (era) {
    case Era::Narrow:
        skeletonBuilder.append("GGGGG"_s);
        break;
    case Era::Short:
        skeletonBuilder.append("GGG"_s);
        break;
    case Era::Long:
        skeletonBuilder.append("GGGG"_s);
        break;
    case Era::None:
        break;
    }

    switch (year) {
    case Year::TwoDigit:
        skeletonBuilder.append("yy"_s);
        break;
    case Year::Numeric:
        skeletonBuilder.append('y');
        break;
    case Year::None:
        break;
    }

    switch (month) {
    case Month::TwoDigit:
        skeletonBuilder.append("MM"_s);
        break;
    case Month::Numeric:
        skeletonBuilder.append('M');
        break;
    case Month::Narrow:
        skeletonBuilder.append("MMMMM"_s);
        break;
    case Month::Short:
        skeletonBuilder.append("MMM"_s);
        break;
    case Month::Long:
        skeletonBuilder.append("MMMM"_s);
        break;
    case Month::None:
        break;
    }

    switch (day) {
    case Day::TwoDigit:
        skeletonBuilder.append("dd"_s);
        break;
    case Day::Numeric:
        skeletonBuilder.append('d');
        break;
    case Day::None:
        break;
    }

    {
        // Specifically, this hour-cycle / hour12 behavior is slightly different from the spec.
        // But the spec behavior is known to cause surprising behaviors, and the spec change is ongoing.
        // We implement SpiderMonkey's behavior.
        //
        //     > No option present: "j"
        //     > hour12 = true: "h"
        //     > hour12 = false: "H"
        //     > hourCycle = h11: "h", plus modifying the resolved pattern to use the hour symbol "K".
        //     > hourCycle = h12: "h", plus modifying the resolved pattern to use the hour symbol "h".
        //     > hourCycle = h23: "H", plus modifying the resolved pattern to use the hour symbol "H".
        //     > hourCycle = h24: "H", plus modifying the resolved pattern to use the hour symbol "k".
        //
        char16_t skeletonCharacter = 'j';
        if (hour12 == TriState::Indeterminate) {
            switch (hourCycle) {
            case HourCycle::None:
                break;
            case HourCycle::H11:
            case HourCycle::H12:
                skeletonCharacter = 'h';
                break;
            case HourCycle::H23:
            case HourCycle::H24:
                skeletonCharacter = 'H';
                break;
            }
        } else {
            if (hour12 == TriState::True)
                skeletonCharacter = 'h';
            else
                skeletonCharacter = 'H';
        }

        switch (hour) {
        case Hour::TwoDigit:
            skeletonBuilder.append(skeletonCharacter);
            skeletonBuilder.append(skeletonCharacter);
            break;
        case Hour::Numeric:
            skeletonBuilder.append(skeletonCharacter);
            break;
        case Hour::None:
            break;
        }
    }

    // dayPeriod must be set after setting hour.
    // https://unicode-org.atlassian.net/browse/ICU-20731
    switch (dayPeriod) {
    case DayPeriod::Narrow:
        skeletonBuilder.append("BBBBB"_s);
        break;
    case DayPeriod::Short:
        skeletonBuilder.append('B');
        break;
    case DayPeriod::Long:
        skeletonBuilder.append("BBBB"_s);
        break;
    case DayPeriod::None:
        break;
    }

    switch (minute) {
    case Minute::TwoDigit:
        skeletonBuilder.append("mm"_s);
        break;
    case Minute::Numeric:
        skeletonBuilder.append('m');
        break;
    case Minute::None:
        break;
    }

    switch (second) {
    case Second::TwoDigit:
        skeletonBuilder.append("ss"_s);
        break;
    case Second::Numeric:
        skeletonBuilder.append('s');
        break;
    case Second::None:
        break;
    }

    for (unsigned i = 0; i < fractionalSecondDigits; ++i)
        skeletonBuilder.append('S');

    switch (timeZoneName) {
    case TimeZoneName::Short:
        skeletonBuilder.append('z');
        break;
    case TimeZoneName::Long:
        skeletonBuilder.append("zzzz"_s);
        break;
    case TimeZoneName::ShortOffset:
        skeletonBuilder.append('O');
        break;
    case TimeZoneName::LongOffset:
        skeletonBuilder.append("OOOO"_s);
        break;
    case TimeZoneName::ShortGeneric:
        skeletonBuilder.append('v');
        break;
    case TimeZoneName::LongGeneric:
        skeletonBuilder.append("vvvv"_s);
        break;
    case TimeZoneName::None:
        break;
    }

    return skeletonBuilder.toString();
}

// https://tc39.github.io/ecma402/#sec-initializedatetimeformat
void IntlDateTimeFormat::initializeDateTimeFormat(JSGlobalObject* globalObject, JSValue locales, JSValue originalOptions, RequiredComponent required, Defaults defaults)
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    Vector<String> requestedLocales = canonicalizeLocaleList(globalObject, locales);
    RETURN_IF_EXCEPTION(scope, void());

    JSObject* options = intlCoerceOptionsToObject(globalObject, originalOptions);
    RETURN_IF_EXCEPTION(scope, void());

    ResolveLocaleOptions localeOptions;

    LocaleMatcher localeMatcher = intlOption<LocaleMatcher>(globalObject, options, vm.propertyNames->localeMatcher, { { "lookup"_s, LocaleMatcher::Lookup }, { "best fit"_s, LocaleMatcher::BestFit } }, "localeMatcher must be either \"lookup\" or \"best fit\""_s, LocaleMatcher::BestFit);
    RETURN_IF_EXCEPTION(scope, void());

    String calendar = intlStringOption(globalObject, options, vm.propertyNames->calendar, { }, { }, { });
    RETURN_IF_EXCEPTION(scope, void());
    if (!calendar.isNull()) {
        if (!isUnicodeLocaleIdentifierType(calendar)) {
            throwRangeError(globalObject, scope, "calendar is not a well-formed calendar value"_s);
            return;
        }
        localeOptions[static_cast<unsigned>(RelevantExtensionKey::Ca)] = calendar.convertToASCIILowercase();
    }

    String numberingSystem = intlStringOption(globalObject, options, vm.propertyNames->numberingSystem, { }, { }, { });
    RETURN_IF_EXCEPTION(scope, void());
    if (!numberingSystem.isNull()) {
        if (!isUnicodeLocaleIdentifierType(numberingSystem)) {
            throwRangeError(globalObject, scope, "numberingSystem is not a well-formed numbering system value"_s);
            return;
        }
        localeOptions[static_cast<unsigned>(RelevantExtensionKey::Nu)] = numberingSystem;
    }

    TriState hour12 = intlBooleanOption(globalObject, options, vm.propertyNames->hour12);
    RETURN_IF_EXCEPTION(scope, void());

    HourCycle hourCycle = intlOption<HourCycle>(globalObject, options, vm.propertyNames->hourCycle, { { "h11"_s, HourCycle::H11 }, { "h12"_s, HourCycle::H12 }, { "h23"_s, HourCycle::H23 }, { "h24"_s, HourCycle::H24 } }, "hourCycle must be \"h11\", \"h12\", \"h23\", or \"h24\""_s, HourCycle::None);
    RETURN_IF_EXCEPTION(scope, void());
    if (hour12 == TriState::Indeterminate) {
        if (hourCycle != HourCycle::None)
            localeOptions[static_cast<unsigned>(RelevantExtensionKey::Hc)] = String(hourCycleString(hourCycle));
    } else {
        // If there is hour12, hourCycle is ignored.
        // We are setting null String explicitly here (localeOptions' entries are std::optional<String>). This leads us to use HourCycle::None later.
        localeOptions[static_cast<unsigned>(RelevantExtensionKey::Hc)] = String();
    }

    const auto& availableLocales = intlDateTimeFormatAvailableLocales();
    auto resolved = resolveLocale(globalObject, availableLocales, requestedLocales, localeMatcher, localeOptions, { RelevantExtensionKey::Ca, RelevantExtensionKey::Hc, RelevantExtensionKey::Nu }, localeData);

    m_locale = resolved.locale;
    if (m_locale.isEmpty()) {
        throwTypeError(globalObject, scope, "failed to initialize DateTimeFormat due to invalid locale"_s);
        return;
    }

    {
        String calendar = resolved.extensions[static_cast<unsigned>(RelevantExtensionKey::Ca)];
        if (!calendar.isNull()) {
            if (auto mapped = mapICUCalendarKeywordToBCP47(calendar))
                calendar = WTF::move(mapped.value());
            // Handling "islamicc" candidate for backward compatibility.
            if (calendar == "islamicc"_s)
                calendar = "islamic-civil"_s;
        }
        m_calendar = WTF::move(calendar);
    }

    hourCycle = parseHourCycle(resolved.extensions[static_cast<unsigned>(RelevantExtensionKey::Hc)]);
    m_numberingSystem = resolved.extensions[static_cast<unsigned>(RelevantExtensionKey::Nu)];
    m_dataLocale = resolved.dataLocale;

    StringBuilder localeBuilder;
    localeBuilder.append(m_dataLocale);
    if (!m_calendar.isNull() || !m_numberingSystem.isNull()) {
        localeBuilder.append("-u"_s);
        if (!m_calendar.isNull())
            localeBuilder.append("-ca-"_s, m_calendar);
        if (!m_numberingSystem.isNull())
            localeBuilder.append("-nu-"_s, m_numberingSystem);
    }
    CString dataLocaleWithExtensions = localeBuilder.toString().utf8();

    JSValue tzValue = jsUndefined();
    if (options) {
        tzValue = options->get(globalObject, vm.propertyNames->timeZone);
        RETURN_IF_EXCEPTION(scope, void());
    }
    TimeZone tz;
    String tzForResolvedOptions;
    if (!tzValue.isUndefined()) {
        String originalTz = tzValue.toWTFString(globalObject);
        RETURN_IF_EXCEPTION(scope, void());
        if (auto minutesValue = ISO8601::parseUTCOffsetInMinutes(originalTz)) {
            int64_t nanoseconds = minutesValue.value() * 60LL * 1000 * 1000 * 1000;
            tz = TimeZone::fromUTCOffset(nanoseconds);
            tzForResolvedOptions = ISO8601::formatTimeZoneOffsetString(nanoseconds);
        } else if (auto resolved = intlAvailableNamedTimeZone(originalTz)) {
            tz = TimeZone::fromID(resolved->id);
            tzForResolvedOptions = resolved->identifier;
        } else {
            String message = tryMakeString("invalid time zone: "_s, originalTz);
            if (!message)
                message = "invalid time zone"_s;
            throwRangeError(globalObject, scope, message);
            return;
        }
    } else {
        tz = vm.dateCache.defaultTimeZone();
        tzForResolvedOptions = tz.toString();
    }
    m_timeZone = tz;
    m_timeZoneForResolvedOptions = WTF::move(tzForResolvedOptions);

    Weekday weekday = intlOption<Weekday>(globalObject, options, vm.propertyNames->weekday, { { "narrow"_s, Weekday::Narrow }, { "short"_s, Weekday::Short }, { "long"_s, Weekday::Long } }, "weekday must be \"narrow\", \"short\", or \"long\""_s, Weekday::None);
    RETURN_IF_EXCEPTION(scope, void());

    Era era = intlOption<Era>(globalObject, options, vm.propertyNames->era, { { "narrow"_s, Era::Narrow }, { "short"_s, Era::Short }, { "long"_s, Era::Long } }, "era must be \"narrow\", \"short\", or \"long\""_s, Era::None);
    RETURN_IF_EXCEPTION(scope, void());

    Year year = intlOption<Year>(globalObject, options, vm.propertyNames->year, { { "2-digit"_s, Year::TwoDigit }, { "numeric"_s, Year::Numeric } }, "year must be \"2-digit\" or \"numeric\""_s, Year::None);
    RETURN_IF_EXCEPTION(scope, void());

    Month month = intlOption<Month>(globalObject, options, vm.propertyNames->month, { { "2-digit"_s, Month::TwoDigit }, { "numeric"_s, Month::Numeric }, { "narrow"_s, Month::Narrow }, { "short"_s, Month::Short }, { "long"_s, Month::Long } }, "month must be \"2-digit\", \"numeric\", \"narrow\", \"short\", or \"long\""_s, Month::None);
    RETURN_IF_EXCEPTION(scope, void());

    Day day = intlOption<Day>(globalObject, options, vm.propertyNames->day, { { "2-digit"_s, Day::TwoDigit }, { "numeric"_s, Day::Numeric } }, "day must be \"2-digit\" or \"numeric\""_s, Day::None);
    RETURN_IF_EXCEPTION(scope, void());

    DayPeriod dayPeriod = intlOption<DayPeriod>(globalObject, options, vm.propertyNames->dayPeriod, { { "narrow"_s, DayPeriod::Narrow }, { "short"_s, DayPeriod::Short }, { "long"_s, DayPeriod::Long } }, "dayPeriod must be \"narrow\", \"short\", or \"long\""_s, DayPeriod::None);
    RETURN_IF_EXCEPTION(scope, void());

    Hour hour = intlOption<Hour>(globalObject, options, vm.propertyNames->hour, { { "2-digit"_s, Hour::TwoDigit }, { "numeric"_s, Hour::Numeric } }, "hour must be \"2-digit\" or \"numeric\""_s, Hour::None);
    RETURN_IF_EXCEPTION(scope, void());

    Minute minute = intlOption<Minute>(globalObject, options, vm.propertyNames->minute, { { "2-digit"_s, Minute::TwoDigit }, { "numeric"_s, Minute::Numeric } }, "minute must be \"2-digit\" or \"numeric\""_s, Minute::None);
    RETURN_IF_EXCEPTION(scope, void());

    Second second = intlOption<Second>(globalObject, options, vm.propertyNames->second, { { "2-digit"_s, Second::TwoDigit }, { "numeric"_s, Second::Numeric } }, "second must be \"2-digit\" or \"numeric\""_s, Second::None);
    RETURN_IF_EXCEPTION(scope, void());

    unsigned fractionalSecondDigits = intlNumberOption(globalObject, options, vm.propertyNames->fractionalSecondDigits, 1, 3, 0);
    RETURN_IF_EXCEPTION(scope, void());

    TimeZoneName timeZoneName = intlOption<TimeZoneName>(globalObject, options, vm.propertyNames->timeZoneName, { { "short"_s, TimeZoneName::Short }, { "long"_s, TimeZoneName::Long }, { "shortOffset"_s, TimeZoneName::ShortOffset }, { "longOffset"_s, TimeZoneName::LongOffset }, { "shortGeneric"_s, TimeZoneName::ShortGeneric}, { "longGeneric"_s, TimeZoneName::LongGeneric } }, "timeZoneName must be \"short\", \"long\", \"shortOffset\", \"longOffset\", \"shortGeneric\", or \"longGeneric\""_s, TimeZoneName::None);
    RETURN_IF_EXCEPTION(scope, void());

    intlStringOption(globalObject, options, vm.propertyNames->formatMatcher, { "basic"_s, "best fit"_s }, "formatMatcher must be either \"basic\" or \"best fit\""_s, "best fit"_s);
    RETURN_IF_EXCEPTION(scope, void());

    m_dateStyle = intlOption<DateTimeStyle>(globalObject, options, vm.propertyNames->dateStyle, { { "full"_s, DateTimeStyle::Full }, { "long"_s, DateTimeStyle::Long }, { "medium"_s, DateTimeStyle::Medium }, { "short"_s, DateTimeStyle::Short } }, "dateStyle must be \"full\", \"long\", \"medium\", or \"short\""_s, DateTimeStyle::None);
    RETURN_IF_EXCEPTION(scope, void());

    m_timeStyle = intlOption<DateTimeStyle>(globalObject, options, vm.propertyNames->timeStyle, { { "full"_s, DateTimeStyle::Full }, { "long"_s, DateTimeStyle::Long }, { "medium"_s, DateTimeStyle::Medium }, { "short"_s, DateTimeStyle::Short } }, "timeStyle must be \"full\", \"long\", \"medium\", or \"short\""_s, DateTimeStyle::None);
    RETURN_IF_EXCEPTION(scope, void());

    Vector<char16_t, 32> patternBuffer;
    if (m_dateStyle != DateTimeStyle::None || m_timeStyle != DateTimeStyle::None) {
        // 30. For each row in Table 1, except the header row, do
        //     i. Let prop be the name given in the Property column of the row.
        //     ii. Let p be opt.[[<prop>]].
        //     iii. If p is not undefined, then
        //         1. Throw a TypeError exception.
        if (weekday != Weekday::None || era != Era::None || year != Year::None || month != Month::None || day != Day::None || dayPeriod != DayPeriod::None || hour != Hour::None || minute != Minute::None || second != Second::None || fractionalSecondDigits != 0 || timeZoneName != TimeZoneName::None) {
            throwTypeError(globalObject, scope, "dateStyle and timeStyle may not be used with other DateTimeFormat options"_s);
            return;
        }

        auto parseUDateFormatStyle = [](DateTimeStyle style) {
            switch (style) {
            case DateTimeStyle::Full:
                return UDAT_FULL;
            case DateTimeStyle::Long:
                return UDAT_LONG;
            case DateTimeStyle::Medium:
                return UDAT_MEDIUM;
            case DateTimeStyle::Short:
                return UDAT_SHORT;
            case DateTimeStyle::None:
                return UDAT_NONE;
            }
            return UDAT_NONE;
        };

        if (required == RequiredComponent::Date && m_timeStyle != DateTimeStyle::None) [[unlikely]] {
            throwTypeError(globalObject, scope, "timeStyle is specified while formatting date is requested"_s);
            return;
        }

        if (required == RequiredComponent::Time && m_dateStyle != DateTimeStyle::None) [[unlikely]] {
            throwTypeError(globalObject, scope, "dateStyle is specified while formatting time is requested"_s);
            return;
        }

        // We cannot use this UDateFormat directly yet because we need to enforce specified hourCycle.
        // First, we create UDateFormat via dateStyle and timeStyle. And then convert it to pattern string.
        // After updating this pattern string with hourCycle, we create a final UDateFormat with the updated pattern string.
        UErrorCode status = U_ZERO_ERROR;
        String timeZoneForICU = m_timeZone.toICUString();
        StringView timeZoneView(timeZoneForICU);
        auto dateFormatFromStyle = std::unique_ptr<UDateFormat, UDateFormatDeleter>(udat_open(parseUDateFormatStyle(m_timeStyle), parseUDateFormatStyle(m_dateStyle), dataLocaleWithExtensions.data(), timeZoneView.upconvertedCharacters(), timeZoneView.length(), nullptr, -1, &status));
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "failed to initialize DateTimeFormat"_s);
            return;
        }
        constexpr bool localized = false; // Aligned with how ICU SimpleDateTimeFormat::format works. We do not need to translate this to localized pattern.
        status = callBufferProducingFunction(udat_toPattern, dateFormatFromStyle.get(), localized, patternBuffer);
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "failed to initialize DateTimeFormat"_s);
            return;
        }

        // It is possible that timeStyle includes dayPeriod, which is sensitive to hour-cycle.
        // If dayPeriod is included, just replacing hour based on hourCycle / hour12 produces strange results.
        // Let's consider about the example. The formatted result looks like "02:12:47 PM Coordinated Universal Time"
        // If we simply replace 02 to 14, this becomes "14:12:47 PM Coordinated Universal Time", this looks strange since "PM" is unnecessary!
        //
        // If the generated pattern's hour12 does not match against the option's one, we retrieve skeleton from the pattern, enforcing hour-cycle,
        // and re-generating the best pattern from the modified skeleton. ICU will look into the generated skeleton, and pick the best format for the request.
        // We do not care about h11 vs. h12 and h23 vs. h24 difference here since this will be later adjusted by replaceHourCycleInPattern.
        //
        // test262/test/intl402/DateTimeFormat/prototype/format/timedatestyle-en.js includes the test for this behavior.
        if (m_timeStyle != DateTimeStyle::None && (hourCycle != HourCycle::None || hour12 != TriState::Indeterminate)) {
            auto isHour12 = [](HourCycle hourCycle) {
                return hourCycle == HourCycle::H11 || hourCycle == HourCycle::H12;
            };
            bool specifiedHour12 = false;
            // If hour12 is specified, we prefer it and ignore hourCycle.
            if (hour12 != TriState::Indeterminate)
                specifiedHour12 = hour12 == TriState::True;
            else
                specifiedHour12 = isHour12(hourCycle);
            HourCycle extractedHourCycle = hourCycleFromPattern(patternBuffer);
            if (extractedHourCycle != HourCycle::None && isHour12(extractedHourCycle) != specifiedHour12) {
                Vector<char16_t, 32> skeleton;
                auto status = callBufferProducingFunction(udatpg_getSkeleton, nullptr, patternBuffer.span().data(), patternBuffer.size(), skeleton);
                if (U_FAILURE(status)) {
                    throwTypeError(globalObject, scope, "failed to initialize DateTimeFormat"_s);
                    return;
                }
                replaceHourCycleInSkeleton(skeleton, specifiedHour12);
                dataLogLnIf(IntlDateTimeFormatInternal::verbose, "replaced:(", StringView { skeleton.span() }, ")");

                patternBuffer = vm.intlCache().getBestDateTimePattern(dataLocaleWithExtensions, skeleton.span(), status);
                if (U_FAILURE(status)) {
                    throwTypeError(globalObject, scope, "failed to initialize DateTimeFormat"_s);
                    return;
                }
            }
        }
    } else {
        bool needDefaults = true;
        if (required == RequiredComponent::Date || required == RequiredComponent::Any) {
            // i. For each property name prop of « "weekday", "year", "month", "day" », do
            //     1. Let value be formatOptions.[[<prop>]].
            //     2. If value is not undefined, let needDefaults be false.
            if (weekday != Weekday::None || year != Year::None || month != Month::None || day != Day::None)
                needDefaults = false;
        }

        if (required == RequiredComponent::Time || required == RequiredComponent::Any) {
            // i. For each property name prop of « "dayPeriod", "hour", "minute", "second", "fractionalSecondDigits" », do
            //     1. Let value be formatOptions.[[<prop>]].
            //     2. If value is not undefined, let needDefaults be false.
            if (dayPeriod != DayPeriod::None || hour != Hour::None || minute != Minute::None || second != Second::None || fractionalSecondDigits != 0)
                needDefaults = false;
        }

        if (needDefaults && (defaults == Defaults::Date || defaults == Defaults::All)) {
            year = Year::Numeric;
            month = Month::Numeric;
            day = Day::Numeric;
        }

        if (needDefaults && (defaults == Defaults::Time || defaults == Defaults::All)) {
            hour = Hour::Numeric;
            minute = Minute::Numeric;
            second = Second::Numeric;
        }

        String skeleton = buildSkeleton(weekday, era, year, month, day, hour12, hourCycle, hour, dayPeriod, minute, second, fractionalSecondDigits, timeZoneName);
        UErrorCode status = U_ZERO_ERROR;
        patternBuffer = vm.intlCache().getBestDateTimePattern(dataLocaleWithExtensions, StringView(skeleton).upconvertedCharacters(), status);
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "failed to initialize DateTimeFormat"_s);
            return;
        }
    }

    // After generating pattern from skeleton, we need to change h11 vs. h12 and h23 vs. h24 if hourCycle is specified.
    if (hourCycle != HourCycle::None)
        replaceHourCycleInPattern(patternBuffer, hourCycle);

    StringView pattern(patternBuffer.span());
    setFormatsFromPattern(pattern);

    dataLogLnIf(IntlDateTimeFormatInternal::verbose, "locale:(", m_locale, "),dataLocale:(", dataLocaleWithExtensions, "),pattern:(", pattern, ")");

    UErrorCode status = U_ZERO_ERROR;
    String timeZoneForICU = m_timeZone.toICUString();
    StringView timeZoneView(timeZoneForICU);
    m_dateFormat = std::unique_ptr<UDateFormat, UDateFormatDeleter>(udat_open(UDAT_PATTERN, UDAT_PATTERN, dataLocaleWithExtensions.data(), timeZoneView.upconvertedCharacters(), timeZoneView.length(), pattern.upconvertedCharacters(), pattern.length(), &status));
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "failed to initialize DateTimeFormat"_s);
        return;
    }

    vm.heap.reportExtraMemoryAllocated(this, estimatedUDateFormatSize);

    // Gregorian calendar should be used from the beginning of ECMAScript time.
    // Failure here means unsupported calendar, and can safely be ignored.
    UCalendar* cal = const_cast<UCalendar*>(udat_getCalendar(m_dateFormat.get()));
    ucal_setGregorianChange(cal, minECMAScriptTime, &status);
}

ASCIILiteral IntlDateTimeFormat::hourCycleString(HourCycle hourCycle)
{
    switch (hourCycle) {
    case HourCycle::H11:
        return "h11"_s;
    case HourCycle::H12:
        return "h12"_s;
    case HourCycle::H23:
        return "h23"_s;
    case HourCycle::H24:
        return "h24"_s;
    case HourCycle::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::weekdayString(Weekday weekday)
{
    switch (weekday) {
    case Weekday::Narrow:
        return "narrow"_s;
    case Weekday::Short:
        return "short"_s;
    case Weekday::Long:
        return "long"_s;
    case Weekday::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::eraString(Era era)
{
    switch (era) {
    case Era::Narrow:
        return "narrow"_s;
    case Era::Short:
        return "short"_s;
    case Era::Long:
        return "long"_s;
    case Era::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::yearString(Year year)
{
    switch (year) {
    case Year::TwoDigit:
        return "2-digit"_s;
    case Year::Numeric:
        return "numeric"_s;
    case Year::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::monthString(Month month)
{
    switch (month) {
    case Month::TwoDigit:
        return "2-digit"_s;
    case Month::Numeric:
        return "numeric"_s;
    case Month::Narrow:
        return "narrow"_s;
    case Month::Short:
        return "short"_s;
    case Month::Long:
        return "long"_s;
    case Month::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::dayString(Day day)
{
    switch (day) {
    case Day::TwoDigit:
        return "2-digit"_s;
    case Day::Numeric:
        return "numeric"_s;
    case Day::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::dayPeriodString(DayPeriod dayPeriod)
{
    switch (dayPeriod) {
    case DayPeriod::Narrow:
        return "narrow"_s;
    case DayPeriod::Short:
        return "short"_s;
    case DayPeriod::Long:
        return "long"_s;
    case DayPeriod::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::hourString(Hour hour)
{
    switch (hour) {
    case Hour::TwoDigit:
        return "2-digit"_s;
    case Hour::Numeric:
        return "numeric"_s;
    case Hour::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::minuteString(Minute minute)
{
    switch (minute) {
    case Minute::TwoDigit:
        return "2-digit"_s;
    case Minute::Numeric:
        return "numeric"_s;
    case Minute::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::secondString(Second second)
{
    switch (second) {
    case Second::TwoDigit:
        return "2-digit"_s;
    case Second::Numeric:
        return "numeric"_s;
    case Second::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::timeZoneNameString(TimeZoneName timeZoneName)
{
    switch (timeZoneName) {
    case TimeZoneName::Short:
        return "short"_s;
    case TimeZoneName::Long:
        return "long"_s;
    case TimeZoneName::ShortOffset:
        return "shortOffset"_s;
    case TimeZoneName::LongOffset:
        return "longOffset"_s;
    case TimeZoneName::ShortGeneric:
        return "shortGeneric"_s;
    case TimeZoneName::LongGeneric:
        return "longGeneric"_s;
    case TimeZoneName::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

ASCIILiteral IntlDateTimeFormat::formatStyleString(DateTimeStyle style)
{
    switch (style) {
    case DateTimeStyle::Full:
        return "full"_s;
    case DateTimeStyle::Long:
        return "long"_s;
    case DateTimeStyle::Medium:
        return "medium"_s;
    case DateTimeStyle::Short:
        return "short"_s;
    case DateTimeStyle::None:
        ASSERT_NOT_REACHED();
        return { };
    }
    ASSERT_NOT_REACHED();
    return { };
}

// https://tc39.es/ecma402/#sec-intl.datetimeformat.prototype.resolvedoptions
JSObject* IntlDateTimeFormat::resolvedOptions(JSGlobalObject* globalObject) const
{
    VM& vm = globalObject->vm();

    if (m_calendar.isNull())
        m_calendar = defaultCalendarForLocale(m_dataLocale);
    if (m_numberingSystem.isNull())
        m_numberingSystem = defaultNumberingSystemForLocale(m_dataLocale);

    JSObject* options = constructEmptyObject(globalObject);
    options->putDirect(vm, vm.propertyNames->locale, jsNontrivialString(vm, m_locale));
    options->putDirect(vm, vm.propertyNames->calendar, jsNontrivialString(vm, m_calendar));
    options->putDirect(vm, vm.propertyNames->numberingSystem, jsNontrivialString(vm, m_numberingSystem));
    options->putDirect(vm, vm.propertyNames->timeZone, jsNontrivialString(vm, m_timeZoneForResolvedOptions));

    if (m_hourCycle != HourCycle::None) {
        options->putDirect(vm, vm.propertyNames->hourCycle, jsNontrivialString(vm, hourCycleString(m_hourCycle)));
        options->putDirect(vm, vm.propertyNames->hour12, jsBoolean(m_hourCycle == HourCycle::H11 || m_hourCycle == HourCycle::H12));
    }

    if (m_dateStyle == DateTimeStyle::None && m_timeStyle == DateTimeStyle::None) {
        if (m_weekday != Weekday::None)
            options->putDirect(vm, vm.propertyNames->weekday, jsNontrivialString(vm, weekdayString(m_weekday)));

        if (m_era != Era::None)
            options->putDirect(vm, vm.propertyNames->era, jsNontrivialString(vm, eraString(m_era)));

        if (m_year != Year::None)
            options->putDirect(vm, vm.propertyNames->year, jsNontrivialString(vm, yearString(m_year)));

        if (m_month != Month::None)
            options->putDirect(vm, vm.propertyNames->month, jsNontrivialString(vm, monthString(m_month)));

        if (m_day != Day::None)
            options->putDirect(vm, vm.propertyNames->day, jsNontrivialString(vm, dayString(m_day)));

        if (m_dayPeriod != DayPeriod::None)
            options->putDirect(vm, vm.propertyNames->dayPeriod, jsNontrivialString(vm, dayPeriodString(m_dayPeriod)));

        if (m_hour != Hour::None)
            options->putDirect(vm, vm.propertyNames->hour, jsNontrivialString(vm, hourString(m_hour)));

        if (m_minute != Minute::None)
            options->putDirect(vm, vm.propertyNames->minute, jsNontrivialString(vm, minuteString(m_minute)));

        if (m_second != Second::None)
            options->putDirect(vm, vm.propertyNames->second, jsNontrivialString(vm, secondString(m_second)));

        if (m_fractionalSecondDigits)
            options->putDirect(vm, vm.propertyNames->fractionalSecondDigits, jsNumber(m_fractionalSecondDigits));

        if (m_timeZoneName != TimeZoneName::None)
            options->putDirect(vm, vm.propertyNames->timeZoneName, jsNontrivialString(vm, timeZoneNameString(m_timeZoneName)));
    } else {
        if (m_dateStyle != DateTimeStyle::None)
            options->putDirect(vm, vm.propertyNames->dateStyle, jsNontrivialString(vm, formatStyleString(m_dateStyle)));

        if (m_timeStyle != DateTimeStyle::None)
            options->putDirect(vm, vm.propertyNames->timeStyle, jsNontrivialString(vm, formatStyleString(m_timeStyle)));
    }

    return options;
}

// ICU 72 uses narrowNoBreakSpace (u202F) and thinSpace (u2009) for the output of Intl.DateTimeFormat.
// However, a lot of real world code (websites[1], Node.js modules[2] etc.) strongly assumes that this output
// only contains normal spaces and these code stops working because of parsing failures. As a workaround
// for this issue, this function replaces narrowNoBreakSpace and thinSpace with normal space.
// This behavior is aligned to SpiderMonkey[3] and V8[4].
// [1]: https://bugzilla.mozilla.org/show_bug.cgi?id=1806042
// [2]: https://github.com/nodejs/node/issues/46123
// [3]: https://hg.mozilla.org/mozilla-central/rev/40e2c54d5618
// [4]: https://chromium.googlesource.com/v8/v8/+/bab790f9165f65a44845b4383c8df7c6c32cf4b3
template<typename Container>
static void NODELETE replaceNarrowNoBreakSpaceOrThinSpaceWithNormalSpace(Container& vector)
{
    // The key of this replacement is that we are not changing size of string.
    // This allows us not to adjust offsets reported from formatToParts / formatRangeToParts
    for (auto& character : vector) {
        if (character == narrowNoBreakSpace || character == thinSpace)
            character = space;
    }
}

// https://tc39.es/ecma402/#sec-formatdatetime
#if PLATFORM(DRIFTSTACK)
// PER-SAFARI-VERSION-BAND timezone-display-name override, mirroring JSDateMath.cpp's
// Date.prototype.toString() table. The iOS CLDR data version ships per Safari release, so the en-US
// LONG ("zzzz", specific non-location) display name for these zones FLIPS across version bands:
//   - Safari <26.4  (verified real-device GTs 18.6 iPhone_16_Pro/Plus, 26.2 iPhone_14): OLD-CLDR
//     metropolitan names (Lagos="West Africa Standard Time", Taipei="Taipei Standard Time",
//     Kamchatka="Petropavlovsk-Kamchatski Standard Time", Apia="Apia Standard Time", ...).
//   - Safari >=26.4 (verified 26.4 iPhone_17/14/15PM, 27.0 iPhone_16PM): NEW-CLDR metropolitan names
//     (Lagos="West Africa Time", Taipei="Taiwan Standard Time", ...) — the launch (#106) values.
// GMT/Etc/GMT oscillate independently: "Coordinated Universal Time" on 18.6 (<26), "Greenwich Mean
// Time" on 26.0-26.x, reverting to "Coordinated Universal Time" on 27.0. Keyed on the
// resolved-options identifier (resolvedOptions().timeZone preserves the *input* id, so "GMT" stays
// "GMT" — distinct from "UTC", which resolves to "Coordinated Universal Time" via macOS ICU on every
// band). All zones have std==dst (none currently observe DST) → single name per zone.
// Bands characterized from real-device BrowserStack tzResolve GTs, NOT the booted simulator (whose
// ICU lags — the Asia/Anadyr / Asia/Kamchatka split lesson). Returns nullptr → fall through to ICU.
static bool driftstackSafariIsNewCLDR()
{
    // NEW-CLDR band = Safari >= 26.4. Unset (no archetype) → NEW (launch default). Token format is
    // DRIFTSTACK_ARCHETYPE "...safari<major>_<minor>..." e.g. "safari26_4".
    int major = 0;
    int minor = 0;
    if (const char* dsArch = getenv("DRIFTSTACK_ARCHETYPE")) {
        std::string_view sv { dsArch };
        auto pos = sv.find("safari");
        if (pos != std::string_view::npos) {
            sv.remove_prefix(pos + 6);
            size_t i = 0;
            for (; i < sv.size() && sv[i] >= '0' && sv[i] <= '9'; ++i)
                major = major * 10 + (sv[i] - '0');
            if (i < sv.size() && sv[i] == '_') {
                ++i;
                for (; i < sv.size() && sv[i] >= '0' && sv[i] <= '9'; ++i)
                    minor = minor * 10 + (sv[i] - '0');
            }
        }
    }
    return major == 0 || major > 26 || (major == 26 && minor >= 4);
}

static const char* driftstackGMTName()
{
    // "Greenwich Mean Time" on Safari 26.0-26.x; "Coordinated Universal Time" on 18.6 (<26) and on
    // 27.0+ (revert). Unset → "Greenwich Mean Time" (launch 26.4 default).
    int major = 0;
    if (const char* dsArch = getenv("DRIFTSTACK_ARCHETYPE")) {
        std::string_view sv { dsArch };
        auto pos = sv.find("safari");
        if (pos != std::string_view::npos) {
            sv.remove_prefix(pos + 6);
            for (char c : sv.substr(0, sv.find('_'))) {
                if (c < '0' || c > '9')
                    break;
                major = major * 10 + (c - '0');
            }
        }
    }
    return (major == 0 || major == 26) ? "Greenwich Mean Time" : "Coordinated Universal Time";
}

static const char* driftstackIPhoneLongZoneName(const String& resolvedTimeZone)
{
    // GMT / Etc/GMT: band-selected name (oscillates CUT->GMT->CUT). UTC/Etc/UTC are NOT overridden —
    // they resolve to "Coordinated Universal Time" via macOS ICU on every captured band.
    if (resolvedTimeZone == "GMT"_s || resolvedTimeZone == "Etc/GMT"_s)
        return driftstackGMTName();

    // newName/oldName == same string for a deterministic selected row (Anadyr; Honolulu's selected
    // real variant). iPhone-14/Safari-26.3 also has a hidden-image GMT-10:00 capture variant. A nullptr
    // band-value means: serve NO override (fall through to macOS ICU) — used for Istanbul pre-26.4,
    // where the real device returns a bare "GMT+03:00" that macOS ICU already produces.
    struct Entry { ASCIILiteral zone; const char* oldName; const char* newName; };
    static constexpr Entry entries[] = {
        { "Africa/Bangui"_s,             "West Africa Standard Time", "West Africa Time" },
        { "Africa/Brazzaville"_s,        "West Africa Standard Time", "West Africa Time" },
        { "Africa/Douala"_s,             "West Africa Standard Time", "West Africa Time" },
        { "Africa/Kinshasa"_s,           "West Africa Standard Time", "West Africa Time" },
        { "Africa/Lagos"_s,              "West Africa Standard Time", "West Africa Time" },
        { "Africa/Libreville"_s,         "West Africa Standard Time", "West Africa Time" },
        { "Africa/Luanda"_s,             "West Africa Standard Time", "West Africa Time" },
        { "Africa/Malabo"_s,             "West Africa Standard Time", "West Africa Time" },
        { "Africa/Ndjamena"_s,           "West Africa Standard Time", "West Africa Time" },
        { "Africa/Niamey"_s,             "West Africa Standard Time", "West Africa Time" },
        { "Africa/Porto-Novo"_s,         "West Africa Standard Time", "West Africa Time" },
        // OLD: ASCII hyphen "Dumont-d’Urville" → NEW: space "Dumont d’Urville". Both U+2019.
        { "Antarctica/DumontDUrville"_s, "Dumont-d\xE2\x80\x99Urville Time", "Dumont d\xE2\x80\x99Urville Time" },
        // Asia/Anadyr: INVARIANT across all bands (distinct metazone from Kamchatka; macOS ICU collapses).
        { "Asia/Anadyr"_s,               "Anadyr Standard Time", "Anadyr Standard Time" },
        { "Asia/Brunei"_s,               "Brunei Darussalam Time", "Brunei Time" },
        { "Asia/Dili"_s,                 "East Timor Time", "Timor-Leste Time" },
        { "Asia/Hovd"_s,                 "Hovd Standard Time", "Khovd Standard Time" },
        { "Asia/Kamchatka"_s,            "Petropavlovsk-Kamchatski Standard Time", "Kamchatka Standard Time" },
        { "Asia/Taipei"_s,               "Taipei Standard Time", "Taiwan Standard Time" },
        { "Pacific/Apia"_s,              "Apia Standard Time", "Samoa Standard Time" },
        // Selected real variant; iPhone-14/26.3 also captured GMT-10:00.
        { "Pacific/Honolulu"_s,          "Hawaii-Aleutian Standard Time", "Hawaii-Aleutian Standard Time" },
        { "Pacific/Midway"_s,            "Samoa Standard Time", "American Samoa Standard Time" },
        { "Pacific/Pago_Pago"_s,         "Samoa Standard Time", "American Samoa Standard Time" },
        { "Pacific/Ponape"_s,            "Ponape Time", "Pohnpei Time" },
        // Türkiye: OLD = explicit "GMT+03:00" — macOS ICU's new CLDR WRONGLY produces "Türkiye Standard
        // Time" pre-26.4, so serve the offset explicitly (real 26.3 iPhone_14 GT longName = "GMT+03:00";
        // verified wl6mgnqcy). NEW (>=26.4) = "Türkiye Standard Time".
        { "Europe/Istanbul"_s,           "GMT+03:00", "T\xC3\xBCrkiye Standard Time" },
        { "Asia/Istanbul"_s,             "GMT+03:00", "T\xC3\xBCrkiye Standard Time" },
    };
    bool isNew = driftstackSafariIsNewCLDR();
    for (auto& entry : entries) {
        if (resolvedTimeZone == entry.zone)
            return isNew ? entry.newName : entry.oldName;
    }
    return nullptr;
}

// G3 (tz-lang audit wponds5b1) — NON-LONG timeZoneName variant overrides. The LONG override
// above fixes only TimeZoneName::Long; the short / shortGeneric / longGeneric / shortOffset /
// longOffset variants fall through to macOS ICU, which diverges from a real iPhone on a handful
// of (zone, variant) cells. Captured BAND-INVARIANT on real iPhone 16 Pro/Safari 18.6 AND
// iPhone 17/Safari 26.5 (reference/realdevice-bs/tznamevariants-iPhone_*):
//   - GMT / Etc/GMT, short        : macOS "GMT"                 -> iPhone "UTC"
//   - GMT / Etc/GMT, longGeneric  : macOS "Greenwich Mean Time" -> iPhone "GMT"
//   - Pacific/Honolulu, longGeneric : macOS "Honolulu Time"     -> iPhone "Hawaii-Aleutian Standard Time"
//   - Asia/Anadyr, longGeneric    : macOS "Petropavlovsk-Kamchatski Standard Time" -> iPhone "Anadyr Standard Time"
// (All other variant cells for all probed zones already match macOS ICU.) Returns nullptr →
// fall through to macOS ICU (the common case for every other zone/variant).
//
// `variant` is the raw IntlDateTimeFormat::TimeZoneName enumerator value (uint8_t underlying) —
// passed as the underlying type because the enum is a private class member and this free function
// can't name it. The members map to the IntlDateTimeFormat.h enum: None=0, Short=1, Long=2,
// ShortOffset=3, LongOffset=4, ShortGeneric=5, LongGeneric=6. Mirrored here for the dispatch.
enum class DriftstackTZNameVariant : uint8_t { None = 0, Short = 1, Long = 2, ShortOffset = 3, LongOffset = 4, ShortGeneric = 5, LongGeneric = 6 };
static const char* driftstackIPhoneZoneNameForVariant(const String& resolvedTimeZone, uint8_t variant)
{
    auto v = static_cast<DriftstackTZNameVariant>(variant);
    if (v == DriftstackTZNameVariant::Long)
        return driftstackIPhoneLongZoneName(resolvedTimeZone);

    bool isGMT = (resolvedTimeZone == "GMT"_s || resolvedTimeZone == "Etc/GMT"_s);
    // GMT/Etc/GMT short + longGeneric are BAND-VARIANT and flip in lockstep with the GMT long name:
    //   OLD (Safari 18.6 / 27+):  short="UTC",  longGeneric="GMT"                  [famA-18_6 GT]
    //   NEW (Safari 26.x):        short="GMT",  longGeneric="Greenwich Mean Time"  [aio-iPhone_17 26.4 GT]
    // Tie to driftstackGMTName() ("Coordinated Universal Time" on OLD bands, else "Greenwich Mean Time") so the
    // whole GMT family is coherent. Previously these were hardcoded to the OLD values unconditionally, so the
    // 26.4 launch archetype served the 18.6 names ('UTC'/'GMT') — a per-minor Intl tell.
    bool gmtIsOld = (driftstackGMTName()[0] == 'C');
    switch (v) {
    case DriftstackTZNameVariant::Short:
        if (isGMT)
            return gmtIsOld ? "UTC" : "GMT";
        return nullptr;
    case DriftstackTZNameVariant::LongGeneric:
        if (isGMT)
            return gmtIsOld ? "GMT" : "Greenwich Mean Time";
        if (resolvedTimeZone == "Pacific/Honolulu"_s)
            return "Hawaii-Aleutian Standard Time";
        if (resolvedTimeZone == "Asia/Anadyr"_s)
            return "Anadyr Standard Time";
        return nullptr;
    default:
        return nullptr;
    }
}

// defect-2 (2026-09-02, A1 measured 24 zone/offset cases either side of Safari 26.4): the ONLY CLDR
// generation difference in the offset-name family is the ZERO offset — OLD CLDR (<26.4) renders it
// "GMT", NEW (>=26.4) renders "GMT+00:00". All 21 non-zero offsets are byte-identical in both
// generations (Tokyo GMT+09:00, Lord Howe GMT+10:30, LA GMT-08:00, NY GMT-04:00, Apia GMT+13:00 —
// half-hours and >12 included), so this rewrites ONLY a zero-offset LongOffset field and moves
// nothing else. A general LongOffset rewrite would move 21 currently-correct renderings.
// ⛔ ShortOffset is deliberately NOT handled: no capture in the corpus carries a shortOffset field,
// so its old-CLDR spelling is UNMEASURED and must not be guessed (a guessed string is a new tell).
//
// ⭐ ONE DEFINITION, FOUR CALL SITES. format(), formatToParts(), formatRange() and formatRangeToParts()
// must return the same zone name for the same options — the intra-object coherence the W3149 comments
// below already state for the #106 zone-name override. The first cut of this fix lived only in
// format(); the tzoffset probe formats via formatToParts(), so the render measured the untouched path
// and the change read as inert on the box. Splitting the predicate (cheap, band+variant only) from the
// rewrite (needs the ICU-rendered field text) lets every site keep its existing "is any override even
// possible?" gate before doing the field-position work.
static bool driftstackOldCLDRZeroOffsetApplies(uint8_t variant)
{
    return static_cast<DriftstackTZNameVariant>(variant) == DriftstackTZNameVariant::LongOffset
        && !driftstackSafariIsNewCLDR();
}

static const char* driftstackOldCLDRZeroOffsetName(uint8_t variant, StringView icuFieldText)
{
    if (!driftstackOldCLDRZeroOffsetApplies(variant))
        return nullptr;
    return icuFieldText == "GMT+00:00"_s ? "GMT" : nullptr;
}

// True for the UDateFormatField values that partTypeString() maps to "timeZoneName".
static bool driftstackIsTimeZoneField(UDateFormatField field)
{
    switch (field) {
    case UDAT_TIMEZONE_FIELD:
    case UDAT_TIMEZONE_RFC_FIELD:
    case UDAT_TIMEZONE_GENERIC_FIELD:
    case UDAT_TIMEZONE_SPECIAL_FIELD:
    case UDAT_TIMEZONE_LOCALIZED_GMT_OFFSET_FIELD:
    case UDAT_TIMEZONE_ISO_FIELD:
    case UDAT_TIMEZONE_ISO_LOCAL_FIELD:
        return true;
    default:
        return false;
    }
}

// G4-Intl (tz-lang audit wponds5b1) — America/Asuncion DST host-leak override for the Intl/ICU
// formatting path. JSDateMath.cpp's G4 fixes only the Date process-zone path (getTimezoneOffset()
// / Date.prototype.toString); Intl.DateTimeFormat keyed on timeZone:"America/Asuncion" reads the
// SAME macOS system ICU tzdata (>=2024b, Paraguay DST abolished -> permanent -03:00). Every captured
// real iPhone still ships the OLDER bundled tzdata that OBSERVES Paraguay DST. Without this override
// a Paraguay-geo session is doubly wrong: Intl reports no-DST (winter==summer==-03:00), AND it is
// INCOHERENT with the Date path (getTimezoneOffset() DST via JSDateMath G4 but Intl no-DST) — a tell
// real iPhones do not have.
//
// ⚠️ GROUND-TRUTH WINDOW (the real-device GTs WIN over JSDateMath.cpp's window — they DISAGREE):
// reference/realdevice-bs/tzoffset-iPhone_17 + tzoffset-iPhone_16_Pro (byte-identical on both)
// capture Asuncion as:
//     Jan 15 (probe "winter") = -03:00 (offsetMin 180, "GMT-03:00") -> STANDARD
//     Jul 15 (probe "summer") = -04:00 (offsetMin 240, "GMT-04:00") -> DST
//     transitions: 2026-03-22T03:00Z (180 -> 240, std -> DST)
//                  2026-10-04T04:00Z (240 -> 180, DST -> std)
// i.e. the DST(-04:00) window is the CONTIGUOUS 4th-Sun-Mar .. 1st-Sun-Oct interval (Paraguay's
// SOUTHERN-hemisphere WINTER per the captured bundled tzdata). This is the COMPLEMENT of the window
// JSDateMath.cpp::driftstackAsuncionDstOffsetMs() implements (which has -04:00 in Oct..Mar, the
// textbook southern-summer rule) — the two share the same transition TIMESTAMPS but invert which
// side is DST. Per the closure contract (GT wins, byte-identical-to-real-device), this function
// matches the GT directly and does NOT reuse JSDateMath's (GT-inverted) window. [FLAGGED: the
// JSDateMath G4 process-zone path is itself GT-inverted for getTimezoneOffset()/Date.toString and
// should be reconciled to this same Mar..Oct window in a separate JSDateMath edit.]
//
// Returns the DST component in milliseconds to ADD to the -03:00 standard offset: -3600000 inside
// the Mar..Oct DST window, 0 (no override needed; macOS ICU's -03:00 is already correct) otherwise.
static constexpr int32_t kDriftstackAsuncionStdOffsetMs = -10800000; // -03:00
// Archetype Safari MAJOR parsed once from DRIFTSTACK_ARCHETYPE ("safariNN_M"); 0 when unset. Band-gates
// the Asuncion DST override below (2026-09-02, A1+A3). Duplicated in JSDateMath.cpp + IntlDateTimeFormat.cpp
// per the deliberate no-shared-header pattern — keep the two identical.
static int driftstackArchetypeSafariMajorForAsuncion()
{
    static const int major = [] {
        const char* a = getenv("DRIFTSTACK_ARCHETYPE");
        if (!a) return 0;
        std::string_view sv { a };
        auto pos = sv.find("safari");
        if (pos == std::string_view::npos) return 0;
        sv.remove_prefix(pos + 6);
        int m = 0;
        for (size_t i = 0; i < sv.size() && sv[i] >= '0' && sv[i] <= '9'; ++i)
            m = m * 10 + (sv[i] - '0');
        return m;
    }();
    return major;
}

static int32_t driftstackAsuncionIntlDstOffsetMs(double millisecondsFromEpoch)
{
    // ⛔ BAND GATE (2026-09-02, A1+A3 corpus): real iPhones observe America/Asuncion DST on Safari <26
    // (18.x) and NOT on 26.x (attributable corpus: 26.x = 187/187 no DST). The prior "26.5 observes it"
    // citation was a provenance-less filename (its one capture has no resolved version); every attributable
    // 26.5 capture reads no-DST. The flip is at the MAJOR (26.0). ⚠ The <26 side is 11/12, NOT unanimous:
    // one 18.6 device carries newer tzdata (2024b) that already dropped Paraguay DST — a per-device
    // tzdata-patch fact the fork cannot see, so <26 is the right pin but a correlation, not a mechanism (the
    // archetype fixes the device image). Unset major (0) → treat as 26+ (no DST), matching launch 26.4 and
    // the dsNewCLDR default. MUST stay identical in the IntlDateTimeFormat twin (getTimezoneOffset window ==
    // Intl window, or a Paraguay session is incoherent).
    {
        int dsMajor = driftstackArchetypeSafariMajorForAsuncion();
        if (dsMajor == 0 || dsMajor >= 26)
            return 0;
    }
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

    // DST STARTS 4th Sun Mar at 00:00 local STD(-03:00): UTC = localMidnight + 03:00.
    int64_t dstStartUTC = utcMidnightMs(y, 3, nthSunday(y, 3, 4)) - kDriftstackAsuncionStdOffsetMs;
    // DST ENDS 1st Sun Oct at 00:00 local DST(-04:00): UTC = localMidnight + 04:00.
    int64_t dstEndUTC = utcMidnightMs(y, 10, nthSunday(y, 10, 1)) - (kDriftstackAsuncionStdOffsetMs - kHourMs);
    // DST(-04:00) active in the CONTIGUOUS Mar..Oct interval (does NOT wrap the year boundary).
    if (utcMs >= dstStartUTC && utcMs < dstEndUTC)
        return -static_cast<int32_t>(kHourMs);
    return 0;
}

// The pre-shift (ms) to apply to the instant fed to ICU so that ICU's no-DST -03:00, applied to the
// shifted instant, yields the real-device -04:00 wall-clock during the Asuncion DST window. Strictly
// gated on the resolved IANA id == "America/Asuncion"; 0 for every other zone (no effect). The shift
// equals the DST delta: feeding (value + dstMs) to ICU makes ICU emit wall = (value + dstMs) + (-03:00)
// = value + (-04:00), the correct DST wall-clock. Outside the DST window dstMs == 0 (no shift).
static int32_t driftstackAsuncionIntlPreShiftMs(const String& resolvedTimeZone, double value)
{
    if (resolvedTimeZone != "America/Asuncion"_s)
        return 0;
    return driftstackAsuncionIntlDstOffsetMs(value);
}

// The iPhone offset-name string to splice into the timeZoneName part during the Asuncion DST window,
// for the OFFSET variants only (shortOffset / longOffset). After the pre-shift the numeric hour parts
// are correct, but ICU still emits its no-DST offset name ("GMT-3" / "GMT-03:00") because Asuncion's
// ICU offset is always -03:00; this overrides it to the DST offset. Forms verified against real-device
// captures (tznamevariants-iPhone_17: e.g. America/New_York std short="GMT-5" long="GMT-05:00") and the
// tzoffset GT (summerLongOffset == "GMT-04:00"). Returns nullptr outside the DST window, for non-offset
// variants (Long/Short/Generic names left to ICU — no GT/probe coverage), or for any non-Asuncion zone.
static const char* driftstackAsuncionIntlOffsetName(const String& resolvedTimeZone, double value, uint8_t variant)
{
    if (resolvedTimeZone != "America/Asuncion"_s)
        return nullptr;
    if (!driftstackAsuncionIntlDstOffsetMs(value))
        return nullptr; // standard (-03:00) window: ICU is already correct.
    auto v = static_cast<DriftstackTZNameVariant>(variant);
    switch (v) {
    case DriftstackTZNameVariant::LongOffset:
        return "GMT-04:00";
    case DriftstackTZNameVariant::ShortOffset:
        return "GMT-4";
    default:
        return nullptr;
    }
}
#endif // PLATFORM(DRIFTSTACK)

JSValue IntlDateTimeFormat::format(JSGlobalObject* globalObject, double value) const
{
    ASSERT(m_dateFormat);

    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    if (!std::isfinite(value))
        return throwRangeError(globalObject, scope, "date value is not finite in DateTimeFormat format()"_s);

#if PLATFORM(DRIFTSTACK)
    // Lock the DriftstackTZNameVariant mirror to the (private) IntlDateTimeFormat::TimeZoneName enum
    // values used by driftstackIPhoneZoneNameForVariant — fail the build if upstream reorders them.
    static_assert(static_cast<uint8_t>(TimeZoneName::None) == static_cast<uint8_t>(DriftstackTZNameVariant::None));
    static_assert(static_cast<uint8_t>(TimeZoneName::Short) == static_cast<uint8_t>(DriftstackTZNameVariant::Short));
    static_assert(static_cast<uint8_t>(TimeZoneName::Long) == static_cast<uint8_t>(DriftstackTZNameVariant::Long));
    static_assert(static_cast<uint8_t>(TimeZoneName::ShortOffset) == static_cast<uint8_t>(DriftstackTZNameVariant::ShortOffset));
    static_assert(static_cast<uint8_t>(TimeZoneName::LongOffset) == static_cast<uint8_t>(DriftstackTZNameVariant::LongOffset));
    static_assert(static_cast<uint8_t>(TimeZoneName::LongGeneric) == static_cast<uint8_t>(DriftstackTZNameVariant::LongGeneric));

    // G4-Intl America/Asuncion DST: pre-shift the instant fed to ICU by the DST delta so ICU's no-DST
    // -03:00 yields the real-device -04:00 wall-clock (hour/day numeric parts) during the Mar..Oct DST
    // window. Strictly 0 for every other zone. (Outside the window the shift is 0 — std -03:00 already
    // matches.) See driftstackAsuncionIntlDstOffsetMs() for the GT-correct window.
    double icuValue = value + static_cast<double>(driftstackAsuncionIntlPreShiftMs(m_timeZoneForResolvedOptions, value));

    // For the iOS/macOS-divergent zones, locate the time-zone field via the field-position iterator
    // and splice in the iPhone-correct display name. Covers the LONG style (the 26 #106 zones), the
    // G3 non-LONG variant overrides (GMT/Etc/GMT short+longGeneric, Honolulu/Anadyr longGeneric), and
    // the Asuncion DST offset-name override (shortOffset "GMT-4" / longOffset "GMT-04:00") — the latter
    // is needed because after the pre-shift ICU still emits its no-DST "GMT-3"/"GMT-03:00" offset name.
    // Zero overhead for every other format() call (common case): both helpers return nullptr and the
    // udat_format path below is unchanged (on icuValue == value).
    if (m_timeZoneName != TimeZoneName::None) {
        const char* iosName = driftstackIPhoneZoneNameForVariant(m_timeZoneForResolvedOptions, static_cast<uint8_t>(m_timeZoneName));
        if (!iosName)
            iosName = driftstackAsuncionIntlOffsetName(m_timeZoneForResolvedOptions, value, static_cast<uint8_t>(m_timeZoneName));
        // defect-2: the old-CLDR zero-offset rewrite (see driftstackOldCLDRZeroOffsetName). It needs the
        // ICU-rendered field text, so the decision happens inside the loop; the cheap band+variant
        // predicate here only decides whether the field-position work is worth doing at all.
        bool maybeZeroOffset = driftstackOldCLDRZeroOffsetApplies(static_cast<uint8_t>(m_timeZoneName));
        if (iosName || maybeZeroOffset) {
            UErrorCode fstatus = U_ZERO_ERROR;
            auto fields = std::unique_ptr<UFieldPositionIterator, UFieldPositionIteratorDeleter>(ufieldpositer_open(&fstatus));
            if (U_SUCCESS(fstatus)) {
                Vector<char16_t, 32> fresult;
                fstatus = callBufferProducingFunction(udat_formatForFields, m_dateFormat.get(), icuValue, fresult, fields.get());
                if (U_SUCCESS(fstatus)) {
                    replaceNarrowNoBreakSpaceOrThinSpaceWithNormalSpace(fresult); // length-preserving; field indices stay valid
                    int32_t b = 0, e = 0;
                    for (;;) {
                        auto ft = ufieldpositer_next(fields.get(), &b, &e);
                        if (ft < 0)
                            break;
                        if (driftstackIsTimeZoneField(UDateFormatField(ft))) {
                            const char* replacement = iosName;
                            if (!replacement) {
                                replacement = driftstackOldCLDRZeroOffsetName(static_cast<uint8_t>(m_timeZoneName),
                                    StringView(fresult.span().subspan(static_cast<size_t>(b), static_cast<size_t>(e - b))));
                            }
                            if (replacement) {
                                auto head = String(fresult.span().first(static_cast<size_t>(b)));
                                auto tail = String(fresult.span().subspan(static_cast<size_t>(e)));
                                return jsString(vm, makeString(head, String::fromUTF8(replacement), tail));
                            }
                            break; // old-CLDR band but the field was not GMT+00:00 → standard ICU output stands.
                        }
                    }
                }
            }
        }
    }
#endif

    Vector<char16_t, 32> result;
#if PLATFORM(DRIFTSTACK)
    // Format the (Asuncion-DST-pre-shifted) instant; icuValue == value for every other zone/instant.
    auto status = callBufferProducingFunction(udat_format, m_dateFormat.get(), icuValue, result, nullptr);
#else
    auto status = callBufferProducingFunction(udat_format, m_dateFormat.get(), value, result, nullptr);
#endif
    if (U_FAILURE(status))
        return throwTypeError(globalObject, scope, "failed to format date value"_s);
    replaceNarrowNoBreakSpaceOrThinSpaceWithNormalSpace(result);

    return jsString(vm, String(WTF::move(result)));
}

static ASCIILiteral partTypeString(UDateFormatField field)
{
    switch (field) {
    case UDAT_ERA_FIELD:
        return "era"_s;
    case UDAT_YEAR_FIELD:
    case UDAT_EXTENDED_YEAR_FIELD:
        return "year"_s;
    case UDAT_YEAR_NAME_FIELD:
        return "yearName"_s;
    case UDAT_MONTH_FIELD:
    case UDAT_STANDALONE_MONTH_FIELD:
        return "month"_s;
    case UDAT_DATE_FIELD:
        return "day"_s;
    case UDAT_HOUR_OF_DAY1_FIELD:
    case UDAT_HOUR_OF_DAY0_FIELD:
    case UDAT_HOUR1_FIELD:
    case UDAT_HOUR0_FIELD:
        return "hour"_s;
    case UDAT_MINUTE_FIELD:
        return "minute"_s;
    case UDAT_SECOND_FIELD:
        return "second"_s;
    case UDAT_FRACTIONAL_SECOND_FIELD:
        return "fractionalSecond"_s;
    case UDAT_DAY_OF_WEEK_FIELD:
    case UDAT_DOW_LOCAL_FIELD:
    case UDAT_STANDALONE_DAY_FIELD:
        return "weekday"_s;
    case UDAT_AM_PM_FIELD:
    case UDAT_AM_PM_MIDNIGHT_NOON_FIELD:
    case UDAT_FLEXIBLE_DAY_PERIOD_FIELD:
        return "dayPeriod"_s;
    case UDAT_TIMEZONE_FIELD:
    case UDAT_TIMEZONE_RFC_FIELD:
    case UDAT_TIMEZONE_GENERIC_FIELD:
    case UDAT_TIMEZONE_SPECIAL_FIELD:
    case UDAT_TIMEZONE_LOCALIZED_GMT_OFFSET_FIELD:
    case UDAT_TIMEZONE_ISO_FIELD:
    case UDAT_TIMEZONE_ISO_LOCAL_FIELD:
        return "timeZoneName"_s;
    case UDAT_RELATED_YEAR_FIELD:
        return "relatedYear"_s;
    // These should not show up because there is no way to specify them in DateTimeFormat options.
    // If they do, they don't fit well into any of known part types, so consider it an "unknown".
    case UDAT_DAY_OF_YEAR_FIELD:
    case UDAT_DAY_OF_WEEK_IN_MONTH_FIELD:
    case UDAT_WEEK_OF_YEAR_FIELD:
    case UDAT_WEEK_OF_MONTH_FIELD:
    case UDAT_YEAR_WOY_FIELD:
    case UDAT_JULIAN_DAY_FIELD:
    case UDAT_MILLISECONDS_IN_DAY_FIELD:
    case UDAT_QUARTER_FIELD:
    case UDAT_STANDALONE_QUARTER_FIELD:
    case UDAT_TIME_SEPARATOR_FIELD:
    // Any newer additions to the UDateFormatField enum should just be considered an "unknown" part.
    default:
        return "unknown"_s;
    }
    return "unknown"_s;
}

// https://tc39.es/ecma402/#sec-formatdatetimetoparts
JSValue IntlDateTimeFormat::formatToParts(JSGlobalObject* globalObject, double value, JSString* sourceType) const
{
    ASSERT(m_dateFormat);

    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    if (!std::isfinite(value))
        return throwRangeError(globalObject, scope, "date value is not finite in DateTimeFormat formatToParts()"_s);

    UErrorCode status = U_ZERO_ERROR;
    auto fields = std::unique_ptr<UFieldPositionIterator, UFieldPositionIteratorDeleter>(ufieldpositer_open(&status));
    if (U_FAILURE(status))
        return throwTypeError(globalObject, scope, "failed to open field position iterator"_s);

#if PLATFORM(DRIFTSTACK)
    // G4-Intl America/Asuncion DST: pre-shift the instant fed to ICU by the DST delta so the formatted
    // hour/day numeric parts reflect the real-device -04:00 wall-clock during the Mar..Oct DST window
    // (the tzoffset probe derives the per-zone offset from exactly these numeric parts). icuValue ==
    // value for every other zone/instant. The timeZoneName offset part is overridden separately below.
    double icuValue = value + static_cast<double>(driftstackAsuncionIntlPreShiftMs(m_timeZoneForResolvedOptions, value));
    Vector<char16_t, 32> result;
    status = callBufferProducingFunction(udat_formatForFields, m_dateFormat.get(), icuValue, result, fields.get());
#else
    Vector<char16_t, 32> result;
    status = callBufferProducingFunction(udat_formatForFields, m_dateFormat.get(), value, result, fields.get());
#endif
    if (U_FAILURE(status))
        return throwTypeError(globalObject, scope, "failed to format date value"_s);
    replaceNarrowNoBreakSpaceOrThinSpaceWithNormalSpace(result);

    JSArray* parts = JSArray::tryCreate(vm, globalObject->arrayStructureForIndexingTypeDuringAllocation(ArrayWithContiguous), 0);
    if (!parts)
        return throwOutOfMemoryError(globalObject, scope);

    StringView resultStringView(result.span());
    auto literalString = jsNontrivialString(vm, "literal"_s);

    int32_t resultLength = result.size();
    int32_t previousEndIndex = 0;
    int32_t beginIndex = 0;
    int32_t endIndex = 0;
    while (previousEndIndex < resultLength) {
        auto fieldType = ufieldpositer_next(fields.get(), &beginIndex, &endIndex);
        if (fieldType < 0)
            beginIndex = endIndex = resultLength;

        if (previousEndIndex < beginIndex) {
            auto value = jsString(vm, resultStringView.substring(previousEndIndex, beginIndex - previousEndIndex));
            JSObject* part = sourceType
                ? createIntlPartObjectWithSource(globalObject, literalString, value, sourceType)
                : createIntlPartObject(globalObject, literalString, value);
            parts->push(globalObject, part);
            RETURN_IF_EXCEPTION(scope, { });
        }
        previousEndIndex = endIndex;

        if (fieldType >= 0) {
            auto type = jsNontrivialString(vm, partTypeString(UDateFormatField(fieldType)));
#if PLATFORM(DRIFTSTACK)
            // Override the zone-name part for the iOS/macOS-divergent zones (see format()): LONG (#106
            // 26 zones), the G3 non-LONG variants (GMT short+longGeneric, Honolulu/Anadyr longGeneric),
            // and the Asuncion DST offset name (shortOffset "GMT-4" / longOffset "GMT-04:00") — the
            // latter keyed on the ORIGINAL instant (the function parameter `value`, not the pre-shifted
            // icuValue) so the DST-window test uses the true UTC instant.
            const char* iosZoneName = nullptr;
            auto icuFieldText = resultStringView.substring(beginIndex, endIndex - beginIndex);
            if (m_timeZoneName != TimeZoneName::None && driftstackIsTimeZoneField(UDateFormatField(fieldType))) {
                iosZoneName = driftstackIPhoneZoneNameForVariant(m_timeZoneForResolvedOptions, static_cast<uint8_t>(m_timeZoneName));
                if (!iosZoneName)
                    iosZoneName = driftstackAsuncionIntlOffsetName(m_timeZoneForResolvedOptions, value, static_cast<uint8_t>(m_timeZoneName));
                // defect-2: old-CLDR zero-offset ("GMT+00:00" -> "GMT" below Safari 26.4). THIS is the
                // path Intl.DateTimeFormat().formatToParts() takes, and it is what the tzoffset probe
                // reads — format() alone does not cover it.
                if (!iosZoneName)
                    iosZoneName = driftstackOldCLDRZeroOffsetName(static_cast<uint8_t>(m_timeZoneName), icuFieldText);
            }
            auto value = iosZoneName
                ? jsString(vm, String::fromUTF8(iosZoneName))
                : jsString(vm, icuFieldText);
#else
            auto value = jsString(vm, resultStringView.substring(beginIndex, endIndex - beginIndex));
#endif
            JSObject* part = sourceType
                ? createIntlPartObjectWithSource(globalObject, type, value, sourceType)
                : createIntlPartObject(globalObject, type, value);
            parts->push(globalObject, part);
            RETURN_IF_EXCEPTION(scope, { });
        }
    }

    return parts;
}

UDateIntervalFormat* IntlDateTimeFormat::createDateIntervalFormatIfNecessary(JSGlobalObject* globalObject)
{
    ASSERT(m_dateFormat);

    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    if (m_dateIntervalFormat)
        return m_dateIntervalFormat.get();

    Vector<char16_t, 32> pattern;
    {
        auto status = callBufferProducingFunction(udat_toPattern, m_dateFormat.get(), false, pattern);
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "failed to initialize DateIntervalFormat"_s);
            return nullptr;
        }
    }

    Vector<char16_t, 32> skeleton;
    {
        auto status = callBufferProducingFunction(udatpg_getSkeleton, nullptr, pattern.span().data(), pattern.size(), skeleton);
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "failed to initialize DateIntervalFormat"_s);
            return nullptr;
        }
    }

    dataLogLnIf(IntlDateTimeFormatInternal::verbose, "interval format pattern:(", String(pattern), "),skeleton:(", String(skeleton), ")");

    // While the pattern is including right HourCycle patterns, UDateIntervalFormat does not follow.
    // We need to enforce HourCycle by setting "hc" extension if it is specified.
    StringBuilder localeBuilder;
    localeBuilder.append(m_dataLocale);
    if (!m_calendar.isNull() || !m_numberingSystem.isNull() || m_hourCycle != HourCycle::None) {
        localeBuilder.append("-u"_s);
        if (!m_calendar.isNull())
            localeBuilder.append("-ca-"_s, m_calendar);
        if (!m_numberingSystem.isNull())
            localeBuilder.append("-nu-"_s, m_numberingSystem);
        if (m_hourCycle != HourCycle::None)
            localeBuilder.append("-hc-"_s, hourCycleString(m_hourCycle));
    }
    CString dataLocaleWithExtensions = localeBuilder.toString().utf8();

    UErrorCode status = U_ZERO_ERROR;
    String timeZoneForICU = m_timeZone.toICUString();
    StringView timeZoneView(timeZoneForICU);
    m_dateIntervalFormat = std::unique_ptr<UDateIntervalFormat, UDateIntervalFormatDeleter>(udtitvfmt_open(dataLocaleWithExtensions.data(), skeleton.span().data(), skeleton.size(), timeZoneView.upconvertedCharacters(), timeZoneView.length(), &status));
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "failed to initialize DateIntervalFormat"_s);
        return nullptr;
    }

    vm.heap.reportExtraMemoryAllocated(this, estimatedUDateIntervalFormatSize);

    return m_dateIntervalFormat.get();
}

static std::unique_ptr<UFormattedDateInterval, ICUDeleter<udtitvfmt_closeResult>> formattedValueFromDateRange(UDateIntervalFormat& dateIntervalFormat, UDateFormat& dateFormat, double startDate, double endDate, UErrorCode& status)
{
    auto result = std::unique_ptr<UFormattedDateInterval, ICUDeleter<udtitvfmt_closeResult>>(udtitvfmt_openResult(&status));
    if (U_FAILURE(status))
        return nullptr;

    // After ICU 67, udtitvfmt_formatToResult's signature is changed.
#if U_ICU_VERSION_MAJOR_NUM >= 67
    // If a date is after Oct 15, 1582, the configuration of gregorian calendar change date in UCalendar does not affect
    // on the formatted string. To ensure that it is after Oct 15 in all timezones, we add one day to gregorian calendar
    // change date in UTC, so that this check can conservatively answer whether the date is definitely after gregorian
    // calendar change date.
    auto definitelyAfterGregorianCalendarChangeDate = [](double millisecondsFromEpoch) {
        constexpr double gregorianCalendarReformDateInUTC = -12219292800000.0;
        return millisecondsFromEpoch >= (gregorianCalendarReformDateInUTC + msPerDay);
    };

    // UFormattedDateInterval does not have a way to configure gregorian calendar change date while ECMAScript requires that
    // gregorian calendar change should not have effect (we are setting ucal_setGregorianChange(cal, minECMAScriptTime, &status) explicitly).
    // As a result, if the input date is older than gregorian calendar change date (Oct 15, 1582), the formatted string becomes
    // julian calendar date.
    // udtitvfmt_formatCalendarToResult API offers the way to set calendar to each date of the input, so that we can use UDateFormat's
    // calendar which is already configured to meet ECMAScript's requirement (effectively clearing gregorian calendar change date).
    //
    // If we can ensure that startDate is after gregorian calendar change date, we can just use udtitvfmt_formatToResult since gregorian
    // calendar change date does not affect on the formatted string.
    //
    // https://unicode-org.atlassian.net/browse/ICU-20705
    if (definitelyAfterGregorianCalendarChangeDate(startDate))
        udtitvfmt_formatToResult(&dateIntervalFormat, startDate, endDate, result.get(), &status);
    else {
        auto createCalendarForDate = [](const UCalendar* calendar, double date, UErrorCode& status) -> std::unique_ptr<UCalendar, ICUDeleter<ucal_close>> {
            auto result = std::unique_ptr<UCalendar, ICUDeleter<ucal_close>>(ucal_clone(calendar, &status));
            if (U_FAILURE(status))
                return nullptr;
            ucal_setMillis(result.get(), date, &status);
            if (U_FAILURE(status))
                return nullptr;
            return result;
        };

        auto calendar = udat_getCalendar(&dateFormat);

        auto startCalendar = createCalendarForDate(calendar, startDate, status);
        if (U_FAILURE(status))
            return nullptr;

        auto endCalendar = createCalendarForDate(calendar, endDate, status);
        if (U_FAILURE(status))
            return nullptr;

        udtitvfmt_formatCalendarToResult(&dateIntervalFormat, startCalendar.get(), endCalendar.get(), result.get(), &status);
    }
#else
    UNUSED_PARAM(dateFormat);
    udtitvfmt_formatToResult(&dateIntervalFormat, result.get(), startDate, endDate, &status);
#endif
    return result;
}

static bool dateFieldsPracticallyEqual(const UFormattedValue* formattedValue, UErrorCode& status)
{
    auto iterator = std::unique_ptr<UConstrainedFieldPosition, ICUDeleter<ucfpos_close>>(ucfpos_open(&status));
    if (U_FAILURE(status))
        return false;

    // We only care about UFIELD_CATEGORY_DATE_INTERVAL_SPAN category.
    ucfpos_constrainCategory(iterator.get(), UFIELD_CATEGORY_DATE_INTERVAL_SPAN, &status);
    if (U_FAILURE(status))
        return false;

    bool hasSpan = ufmtval_nextPosition(formattedValue, iterator.get(), &status);
    if (U_FAILURE(status))
        return false;

    return !hasSpan;
}

JSValue IntlDateTimeFormat::formatRange(JSGlobalObject* globalObject, double startDate, double endDate)
{
    ASSERT(m_dateFormat);

    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    // http://tc39.es/proposal-intl-DateTimeFormat-formatRange/#sec-partitiondatetimerangepattern
    startDate = timeClip(startDate);
    endDate = timeClip(endDate);
    if (std::isnan(startDate) || std::isnan(endDate)) {
        throwRangeError(globalObject, scope, "Passed date is out of range"_s);
        return { };
    }

    auto* dateIntervalFormat = createDateIntervalFormatIfNecessary(globalObject);
    RETURN_IF_EXCEPTION(scope, { });

    UErrorCode status = U_ZERO_ERROR;
    auto result = formattedValueFromDateRange(*dateIntervalFormat, *m_dateFormat, startDate, endDate, status);
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }

    // UFormattedValue is owned by UFormattedDateInterval. We do not need to close it.
    auto formattedValue = udtitvfmt_resultAsValue(result.get(), &status);
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }

    // If the formatted parts of startDate and endDate are the same, it is possible that the resulted string does not look like range.
    // For example, if the requested format only includes "year" and startDate and endDate are the same year, the result just contains one year.
    // In that case, startDate and endDate are *practically-equal* (spec term), and we generate parts as we call `formatToParts(startDate)` with
    // `source: "shared"` additional fields.
    bool equal = dateFieldsPracticallyEqual(formattedValue, status);
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }

    if (equal)
        RELEASE_AND_RETURN(scope, format(globalObject, startDate));

    int32_t formattedStringLength = 0;
    const char16_t* formattedStringPointer = ufmtval_getString(formattedValue, &formattedStringLength, &status);
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }
    Vector<char16_t, 32> buffer(std::span<const char16_t> { formattedStringPointer, static_cast<size_t>(formattedStringLength) });
    replaceNarrowNoBreakSpaceOrThinSpaceWithNormalSpace(buffer);

#if PLATFORM(DRIFTSTACK)
    // W3149 (2nd-audit): mirror format()'s timeZoneName splice into the NON-equal interval branch (the
    // equal branch above already delegates to format(), which is covered). Without this, formatRange
    // leaks the HOST ICU display name for the 26 iOS/macOS-divergent zones (e.g. "Taiwan Standard Time"
    // vs iPhone "Taipei Standard Time") while format()/formatToParts serve the iPhone name — an intra-object
    // coherence tell. Gated on driftstackIPhoneZoneNameForVariant returning non-null, so every common range
    // (no timeZoneName / non-divergent zone) is byte-UNCHANGED. Field indices are valid on `buffer`
    // (space-normalize is length-preserving). Any ICU failure falls through to the un-spliced return.
    // (Asuncion's DST offset-name is intentionally NOT spliced here — it needs the hour/day pre-shift to
    // stay coherent, which formatRange does not apply; that is a separate, narrower residual.)
    if (m_timeZoneName != TimeZoneName::None) {
        const char* iosName = driftstackIPhoneZoneNameForVariant(m_timeZoneForResolvedOptions, static_cast<uint8_t>(m_timeZoneName));
        // defect-2: the old-CLDR zero-offset rewrite applies here too, or formatRange would serve
        // "GMT+00:00" on a <26.4 band while format()/formatToParts serve "GMT" — the same intra-object
        // coherence tell this block was written to close for the #106 zone names.
        bool maybeZeroOffset = driftstackOldCLDRZeroOffsetApplies(static_cast<uint8_t>(m_timeZoneName));
        if (iosName || maybeZeroOffset) {
            UErrorCode zstatus = U_ZERO_ERROR;
            auto ziter = std::unique_ptr<UConstrainedFieldPosition, ICUDeleter<ucfpos_close>>(ucfpos_open(&zstatus));
            if (U_SUCCESS(zstatus)) {
                for (;;) {
                    bool znext = ufmtval_nextPosition(formattedValue, ziter.get(), &zstatus);
                    if (U_FAILURE(zstatus) || !znext)
                        break;
                    if (ucfpos_getCategory(ziter.get(), &zstatus) != UFIELD_CATEGORY_DATE || U_FAILURE(zstatus))
                        continue;
                    int32_t zfield = ucfpos_getField(ziter.get(), &zstatus);
                    if (U_FAILURE(zstatus) || zfield < 0 || !driftstackIsTimeZoneField(UDateFormatField(zfield)))
                        continue;
                    int32_t zb = 0, ze = 0;
                    ucfpos_getIndexes(ziter.get(), &zb, &ze, &zstatus);
                    if (U_FAILURE(zstatus) || zb < 0 || zb > ze || ze > static_cast<int32_t>(buffer.size()))
                        break;
                    const char* replacement = iosName;
                    if (!replacement) {
                        replacement = driftstackOldCLDRZeroOffsetName(static_cast<uint8_t>(m_timeZoneName),
                            StringView(buffer.span().subspan(static_cast<size_t>(zb), static_cast<size_t>(ze - zb))));
                    }
                    if (!replacement)
                        break; // old-CLDR band but the field was not GMT+00:00 → un-spliced ICU output stands.
                    auto head = String(buffer.span().first(static_cast<size_t>(zb)));
                    auto tail = String(buffer.span().subspan(static_cast<size_t>(ze)));
                    return jsString(vm, makeString(head, String::fromUTF8(replacement), tail));
                }
            }
        }
    }
#endif

    return jsString(vm, String(WTF::move(buffer)));
}

JSValue IntlDateTimeFormat::formatRangeToParts(JSGlobalObject* globalObject, double startDate, double endDate)
{
    ASSERT(m_dateFormat);

    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    // http://tc39.es/proposal-intl-DateTimeFormat-formatRange/#sec-partitiondatetimerangepattern
    startDate = timeClip(startDate);
    endDate = timeClip(endDate);
    if (std::isnan(startDate) || std::isnan(endDate)) {
        throwRangeError(globalObject, scope, "Passed date is out of range"_s);
        return { };
    }

    auto* dateIntervalFormat = createDateIntervalFormatIfNecessary(globalObject);
    RETURN_IF_EXCEPTION(scope, { });

    UErrorCode status = U_ZERO_ERROR;
    auto result = formattedValueFromDateRange(*dateIntervalFormat, *m_dateFormat, startDate, endDate, status);
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }

    // UFormattedValue is owned by UFormattedDateInterval. We do not need to close it.
    auto formattedValue = udtitvfmt_resultAsValue(result.get(), &status);
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }

    auto sharedString = jsNontrivialString(vm, "shared"_s);

    // If the formatted parts of startDate and endDate are the same, it is possible that the resulted string does not look like range.
    // For example, if the requested format only includes "year" and startDate and endDate are the same year, the result just contains one year.
    // In that case, startDate and endDate are *practically-equal* (spec term), and we generate parts as we call `formatToParts(startDate)` with
    // `source: "shared"` additional fields.
    bool equal = dateFieldsPracticallyEqual(formattedValue, status);
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }

    if (equal)
        RELEASE_AND_RETURN(scope, formatToParts(globalObject, startDate, sharedString));

    // ICU produces ranges for the formatted string, and we construct parts array from that.
    // For example, startDate = Jan 3, 2019, endDate = Jan 5, 2019 with en-US locale is,
    //
    // Formatted string: "1/3/2019 – 1/5/2019"
    //                    | | |  |   | | |  |
    //                    B C |  |   F G |  |
    //                    |   +-D+   |   +-H+
    //                    |      |   |      |
    //                    +--A---+   +--E---+
    //
    // Ranges ICU generates:
    //     A:    (0, 8)   UFIELD_CATEGORY_DATE_INTERVAL_SPAN startRange
    //     B:    (0, 1)   UFIELD_CATEGORY_DATE month
    //     C:    (2, 3)   UFIELD_CATEGORY_DATE day
    //     D:    (4, 8)   UFIELD_CATEGORY_DATE year
    //     E:    (11, 19) UFIELD_CATEGORY_DATE_INTERVAL_SPAN endRange
    //     F:    (11, 12) UFIELD_CATEGORY_DATE month
    //     G:    (13, 14) UFIELD_CATEGORY_DATE day
    //     H:    (15, 19) UFIELD_CATEGORY_DATE year
    //
    //  We use UFIELD_CATEGORY_DATE_INTERVAL_SPAN range to determine each part is either "startRange", "endRange", or "shared".
    //  It is guaranteed that UFIELD_CATEGORY_DATE_INTERVAL_SPAN comes first before any other parts including that range.
    //  For example, in the above formatted string, " – " is "shared" part. For UFIELD_CATEGORY_DATE ranges, we generate corresponding
    //  part object with types such as "month". And non populated parts (e.g. "/") become "literal" parts.
    //  In the above case, expected parts are,
    //
    //     { type: "month", value: "1", source: "startRange" },
    //     { type: "literal", value: "/", source: "startRange" },
    //     { type: "day", value: "3", source: "startRange" },
    //     { type: "literal", value: "/", source: "startRange" },
    //     { type: "year", value: "2019", source: "startRange" },
    //     { type: "literal", value: " - ", source: "shared" },
    //     { type: "month", value: "1", source: "endRange" },
    //     { type: "literal", value: "/", source: "endRange" },
    //     { type: "day", value: "5", source: "endRange" },
    //     { type: "literal", value: "/", source: "endRange" },
    //     { type: "year", value: "2019", source: "endRange" },
    //

    JSArray* parts = JSArray::tryCreate(vm, globalObject->arrayStructureForIndexingTypeDuringAllocation(ArrayWithContiguous), 0);
    if (!parts) {
        throwOutOfMemoryError(globalObject, scope);
        return { };
    }

    int32_t formattedStringLength = 0;
    const char16_t* formattedStringPointer = ufmtval_getString(formattedValue, &formattedStringLength, &status);
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }
    Vector<char16_t, 32> buffer(std::span<const char16_t> { formattedStringPointer, static_cast<size_t>(formattedStringLength) });
    replaceNarrowNoBreakSpaceOrThinSpaceWithNormalSpace(buffer);

    StringView resultStringView(buffer.span());

    // We care multiple categories (UFIELD_CATEGORY_DATE and UFIELD_CATEGORY_DATE_INTERVAL_SPAN).
    // So we do not constraint iterator.
    auto iterator = std::unique_ptr<UConstrainedFieldPosition, ICUDeleter<ucfpos_close>>(ucfpos_open(&status));
    if (U_FAILURE(status)) {
        throwTypeError(globalObject, scope, "Failed to format date interval"_s);
        return { };
    }

    auto startRangeString = jsNontrivialString(vm, "startRange"_s);
    auto endRangeString = jsNontrivialString(vm, "endRange"_s);
    auto literalString = jsNontrivialString(vm, "literal"_s);

    WTF::Range<int32_t> startRange { -1, -1 };
    WTF::Range<int32_t> endRange { -1, -1 };

    auto createPart = [&] (JSString* type, int32_t beginIndex, int32_t length) {
        auto sourceType = [&](int32_t index) -> JSString* {
            if (startRange.contains(index))
                return startRangeString;
            if (endRange.contains(index))
                return endRangeString;
            return sharedString;
        };

        auto value = jsString(vm, resultStringView.substring(beginIndex, length));
        return createIntlPartObjectWithSource(globalObject, type, value, sourceType(beginIndex));
    };

#if PLATFORM(DRIFTSTACK)
    // W3149 (2nd-audit): the iPhone timeZoneName override for the 26 iOS/macOS-divergent zones, spliced
    // into the timeZoneName part below so formatRangeToParts stays coherent with format()/formatToParts
    // (which serve the iPhone name). nullptr (common case) => the ICU substring value is used unchanged.
    const char* iosZoneName = nullptr;
    if (m_timeZoneName != TimeZoneName::None)
        iosZoneName = driftstackIPhoneZoneNameForVariant(m_timeZoneForResolvedOptions, static_cast<uint8_t>(m_timeZoneName));
    // defect-2: the old-CLDR zero-offset rewrite. Unlike iosZoneName it depends on the ICU-rendered
    // field text, so only the cheap band+variant predicate can be hoisted here; the rewrite itself
    // happens at the timeZoneName part below.
    bool maybeZeroOffset = m_timeZoneName != TimeZoneName::None
        && driftstackOldCLDRZeroOffsetApplies(static_cast<uint8_t>(m_timeZoneName));
#endif

    int32_t resultLength = resultStringView.length();
    int32_t previousEndIndex = 0;
    while (true) {
        bool next = ufmtval_nextPosition(formattedValue, iterator.get(), &status);
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "Failed to format date interval"_s);
            return { };
        }
        if (!next)
            break;

        int32_t category = ucfpos_getCategory(iterator.get(), &status);
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "Failed to format date interval"_s);
            return { };
        }

        int32_t fieldType = ucfpos_getField(iterator.get(), &status);
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "Failed to format date interval"_s);
            return { };
        }

        int32_t beginIndex = 0;
        int32_t endIndex = 0;
        ucfpos_getIndexes(iterator.get(), &beginIndex, &endIndex, &status);
        if (U_FAILURE(status)) {
            throwTypeError(globalObject, scope, "Failed to format date interval"_s);
            return { };
        }

        dataLogLnIf(IntlDateTimeFormatInternal::verbose, category, " ", fieldType, " (", beginIndex, ", ", endIndex, ")");

        if (category != UFIELD_CATEGORY_DATE && category != UFIELD_CATEGORY_DATE_INTERVAL_SPAN)
            continue;
        if (category == UFIELD_CATEGORY_DATE && fieldType < 0)
            continue;

        if (previousEndIndex < beginIndex) {
            JSObject* part = createPart(literalString, previousEndIndex, beginIndex - previousEndIndex);
            parts->push(globalObject, part);
            RETURN_IF_EXCEPTION(scope, { });
            previousEndIndex = beginIndex;
        }

        if (category == UFIELD_CATEGORY_DATE_INTERVAL_SPAN) {
            // > The special field category UFIELD_CATEGORY_DATE_INTERVAL_SPAN is used to indicate which datetime
            // > primitives came from which arguments: 0 means fromCalendar, and 1 means toCalendar. The span category
            // > will always occur before the corresponding fields in UFIELD_CATEGORY_DATE in the nextPosition() iterator.
            // from ICU comment. So, field 0 is startRange, field 1 is endRange.
            if (!fieldType)
                startRange = WTF::Range<int32_t>(beginIndex, endIndex);
            else {
                ASSERT(fieldType == 1);
                endRange = WTF::Range<int32_t>(beginIndex, endIndex);
            }
            continue;
        }

        ASSERT(category == UFIELD_CATEGORY_DATE);

        auto type = jsNontrivialString(vm, partTypeString(UDateFormatField(fieldType)));
#if PLATFORM(DRIFTSTACK)
        // W3149: for a divergent zone, emit the iPhone timeZoneName value instead of the host ICU substring
        // (keeps formatRangeToParts coherent with format()/formatToParts). source follows the field position.
        if ((iosZoneName || maybeZeroOffset) && driftstackIsTimeZoneField(UDateFormatField(fieldType))) {
            const char* zoneName = iosZoneName;
            if (!zoneName) {
                // defect-2: rewrite ONLY the new-CLDR zero-offset form; anything else is band-invariant
                // and must fall through to the ICU substring the generic part-builder below emits.
                zoneName = driftstackOldCLDRZeroOffsetName(static_cast<uint8_t>(m_timeZoneName),
                    resultStringView.substring(beginIndex, endIndex - beginIndex));
            }
            if (zoneName) {
                auto zoneSource = [&](int32_t index) -> JSString* {
                    if (startRange.contains(index))
                        return startRangeString;
                    if (endRange.contains(index))
                        return endRangeString;
                    return sharedString;
                };
                auto zoneValue = jsString(vm, String::fromUTF8(zoneName));
                JSObject* zonePart = createIntlPartObjectWithSource(globalObject, type, zoneValue, zoneSource(beginIndex));
                parts->push(globalObject, zonePart);
                RETURN_IF_EXCEPTION(scope, { });
                previousEndIndex = endIndex;
                continue;
            }
        }
#endif
        JSObject* part = createPart(type, beginIndex, endIndex - beginIndex);
        parts->push(globalObject, part);
        RETURN_IF_EXCEPTION(scope, { });
        previousEndIndex = endIndex;
    }

    if (previousEndIndex < resultLength) {
        JSObject* part = createPart(literalString, previousEndIndex, resultLength - previousEndIndex);
        parts->push(globalObject, part);
        RETURN_IF_EXCEPTION(scope, { });
    }

    return parts;
}


} // namespace JSC

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
