/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#if ENABLE(WEBGL)
#include "WebGLDebugShaders.h"

#include "WebGLShader.h"

#include <wtf/TZoneMallocInlines.h>
#if PLATFORM(DRIFTSTACK)
#include <wtf/text/StringCommon.h>
#include <wtf/text/WTFString.h>
#endif

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(WebGLDebugShaders);

WebGLDebugShaders::WebGLDebugShaders(WebGLRenderingContextBase& context)
    : WebGLExtension(context, WebGLExtensionName::WebGLDebugShaders)
{
    protect(context.graphicsContextGL())->enableExtension(GCGLExtension::ANGLE_translated_shader_source);
}

WebGLDebugShaders::~WebGLDebugShaders() = default;

bool WebGLDebugShaders::supported(GraphicsContextGL& context)
{
    return context.supportsExtension(GCGLExtension::ANGLE_translated_shader_source);
}

#if PLATFORM(DRIFTSTACK)
// §11 / Task #15: the fork's bundled ANGLE (commit c04bb283b5ed, 2026-04-27) is a
// NEWER revision than iPhone Safari 26.4's, so getTranslatedShaderSource (ANGLE→MSL)
// leaks the true engine version via two STRUCTURAL, deterministic differences that
// are IDENTICAL across every shader (verified vs real iPhone 17/Safari 26.4 over 3
// distinct vertex+fragment shaders — they are ANGLE-version artifacts, not shader-
// content): (1) ANGLEUniformBlock field order, (2) the vertex-only gl_PointSize
// [[point_size]] output (iPhone's older ANGLE omits it). getTranslatedShaderSource is
// an INSPECTION-only API (the string is not recompiled), so rewriting the returned
// text to the iPhone-canonical form makes a fingerprinter read iPhone-26.4-identical
// MSL without affecting actual rendering. No-op (pattern-not-found) on shaders/ANGLE
// revs that don't contain these exact blocks. (V-WEBGL-§11-DIVERGENCE-CONFIRMED.)
static String driftstackCanonicalizeTranslatedMSL(const String& msl)
{
    String out = msl;
    // (1) ANGLEUniformBlock: reorder the first 6 fields to iPhone's order
    //     (ANGLE_acbBufferOffsets first; ANGLE_dither before ANGLE_misc). The
    //     trailing 4 fields are already identical, so only the prefix is swapped.
    out = makeStringByReplacingAll(out,
        "  metal::float2 ANGLE_depthRange;\n  uint32_t ANGLE_renderArea;\n  uint32_t ANGLE_flipXY;\n  uint32_t ANGLE_misc;\n  uint32_t ANGLE_dither;\n  metal::uint2 ANGLE_acbBufferOffsets;\n"_s,
        "  metal::uint2 ANGLE_acbBufferOffsets;\n  metal::float2 ANGLE_depthRange;\n  uint32_t ANGLE_renderArea;\n  uint32_t ANGLE_flipXY;\n  uint32_t ANGLE_dither;\n  uint32_t ANGLE_misc;\n"_s);
    // (2) gl_PointSize output (vertex shaders only) — iPhone's ANGLE omits it.
    out = makeStringByReplacingAll(out, "  float gl_PointSize [[point_size]];\n"_s, ""_s);
    out = makeStringByReplacingAll(out, "    ANGLE_vertexOut.gl_PointSize = 1.0f;\n"_s, ""_s);
    return out;
}
#endif

String WebGLDebugShaders::getTranslatedShaderSource(WebGLShader& shader)
{
    if (isContextLost())
        return String();
    Ref context = this->context();
    if (!context->validateWebGLObject("getTranslatedShaderSource"_s, shader))
        return emptyString();
    String translated = String::fromUTF8(protect(context->graphicsContextGL())->getTranslatedShaderSourceANGLE(shader.object()).span());
#if PLATFORM(DRIFTSTACK)
    return driftstackCanonicalizeTranslatedMSL(translated);
#else
    return translated;
#endif
}

} // namespace WebCore

#endif // ENABLE(WEBGL)
