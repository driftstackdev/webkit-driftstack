/*
 * Copyright (C) 2022 Apple Inc. All rights reserved.
 * Copyright (C) 2012 Motorola Mobility Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Motorola Mobility Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
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
#include "DOMCSSNamespace.h"

#include "CSSMarkup.h"
#include "CSSParser.h"
#include "CSSPropertyNames.h"
#include "CSSPropertyParser.h"
#include "CSSSupportsParser.h"
#include "Document.h"
#include "HighlightRegistry.h"
#include "MutableStyleProperties.h"
#include "Settings.h"
#include "StyleProperties.h"
#include <wtf/text/StringBuilder.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

bool DOMCSSNamespace::supports(Document& document, const String& property, const String& value)
{
    CSSParserContext parserContext(document);
    parserContext.mode = HTMLStandardMode;

    auto propertyNameWithoutWhitespace = property;

#if PLATFORM(DRIFTSTACK)
    // V-260 / W1460 CORRECTION: the original V-259 CSS.supports() reference was iOS 18.6 (a Family-A
    // archetype), which genuinely lacks these — so returning false is correct THERE. But the block was
    // UNCONDITIONAL, wrongly forcing false on the 26.4 LAUNCH archetype too, where a real iPhone-17 /
    // Safari-26.4 returns TRUE (W1450 /aio diff vs real). This unconditional short-circuit — running
    // BEFORE isExposed/parseValue — is precisely the "settings don't propagate / needs a backport"
    // mystery of W1451/W1453: every settings layer WAS enabled, but this override returned false first.
    // Gate it on the per-archetype settings: Family A (anchor/scroll-driven disabled by the WebPage.cpp
    // Family-A hook) still returns false; 26.4 (settings default-true) falls through to isExposed /
    // parseValue and returns the real true. (isExposed already gates anchor-name on
    // cssAnchorPositioningEnabled; the version-keyed block documents intent + covers the
    // animation-timeline VALUE, which isExposed does not gate.)
    auto folded = property.convertToASCIILowercase();
    if ((folded == "anchor-name"_s || folded == "position-anchor"_s) && !document.settings().cssAnchorPositioningEnabled())
        return false;
    if (folded == "animation-timeline"_s && !document.settings().scrollDrivenAnimationsEnabled()
        && (value.contains("scroll("_s) || value.contains("view("_s)))
        return false;
#endif

    CSSPropertyID propertyID = cssPropertyID(propertyNameWithoutWhitespace);
    if (propertyID == CSSPropertyInvalid && isCustomPropertyName(propertyNameWithoutWhitespace)) {
        auto dummyStyle = MutableStyleProperties::create();
        return CSSParser::parseCustomPropertyValue(dummyStyle, AtomString { propertyNameWithoutWhitespace }, value, IsImportant::No, parserContext) != CSSParser::ParseResult::Error;
    }

    if (!isExposed(propertyID, &document.settings()))
        return false;

    if (CSSProperty::isDescriptorOnly(propertyID))
        return false;

    if (propertyID == CSSPropertyInvalid)
        return false;

    if (value.isEmpty())
        return false;

    auto dummyStyle = MutableStyleProperties::create();
    return CSSParser::parseValue(dummyStyle, propertyID, value, IsImportant::No, parserContext) != CSSParser::ParseResult::Error;
}

bool DOMCSSNamespace::supports(Document& document, const String& conditionText)
{
    CSSParserContext context(document);
    context.mode = HTMLStandardMode;

    return CSSSupportsParser::supportsCondition(conditionText, context, CSSSupportsParser::ParsingMode::AllowBareDeclarationAndGeneralEnclosed) == CSSSupportsParser::Supported;
}

String DOMCSSNamespace::escape(const String& ident)
{
    StringBuilder builder;
    serializeIdentifier(builder, ident);
    return builder.toString();
}

HighlightRegistry& DOMCSSNamespace::highlights(Document& document)
{
    return document.highlightRegistry();
}

}
