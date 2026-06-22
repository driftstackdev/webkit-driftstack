/*
 * Driftstack WebGL extension allowlist — §11.D Task #89.
 *
 * See DriftstackWebGLExtensionAllowlist.h for rationale and empirical
 * provenance.
 */

#include "config.h"

#if PLATFORM(DRIFTSTACK)

#include "DriftstackWebGLExtensionAllowlist.h"

#include <cstdlib>
#include <string_view>
#include <wtf/NeverDestroyed.h>
#include <wtf/HashSet.h>

namespace WebCore {
namespace Driftstack {

// Empirical iPhone canonical extension set (51 entries, identical across
// Family A and Family B).  Initial 50-entry list verified n=3 per archetype
// on 2026-05-20 from reference/iphone17_ios18_7_safari26_4/fingerprint-v2/*
// and reference/iphone16pro_ios18_6_safari18_6/fingerprint-v2/* via v2
// fingerprint capture page.
//
// Wave 29-499 §11.D r2 (2026-05-20 r53 cumrig run vs canonical REF
// 2026-05-04T19-24-11Z_real-iphone-recapture.json): added
// `NV_shader_noperspective_interpolation` — v2-fp capture missed it but
// real-iPhone cumrig REF exposed it. Cumrig REF (full real-iPhone capture)
// is more comprehensive than the v2-fp page's WebGL probe; cumrig REF wins
// when v2-fp disagrees.
static const HashSet<String>& iphoneCanonicalSet()
{
    static NeverDestroyed<HashSet<String>> set = HashSet<String> {
        "ANGLE_instanced_arrays"_s,
        "EXT_blend_minmax"_s,
        "EXT_clip_control"_s,
        "EXT_color_buffer_float"_s,
        "EXT_color_buffer_half_float"_s,
        "EXT_conservative_depth"_s,
        "EXT_depth_clamp"_s,
        "EXT_float_blend"_s,
        "EXT_frag_depth"_s,
        "EXT_polygon_offset_clamp"_s,
        "EXT_render_snorm"_s,
        "EXT_sRGB"_s,
        "EXT_shader_texture_lod"_s,
        "EXT_texture_compression_bptc"_s,
        "EXT_texture_compression_rgtc"_s,
        "EXT_texture_filter_anisotropic"_s,
        "EXT_texture_mirror_clamp_to_edge"_s,
        "EXT_texture_norm16"_s,
        "KHR_parallel_shader_compile"_s,
        "NV_shader_noperspective_interpolation"_s,
        "OES_draw_buffers_indexed"_s,
        "OES_element_index_uint"_s,
        "OES_fbo_render_mipmap"_s,
        "OES_sample_variables"_s,
        "OES_shader_multisample_interpolation"_s,
        "OES_standard_derivatives"_s,
        "OES_texture_float"_s,
        "OES_texture_float_linear"_s,
        "OES_texture_half_float"_s,
        "OES_texture_half_float_linear"_s,
        "OES_vertex_array_object"_s,
        "WEBGL_blend_func_extended"_s,
        "WEBGL_clip_cull_distance"_s,
        "WEBGL_color_buffer_float"_s,
        "WEBGL_compressed_texture_astc"_s,
        "WEBGL_compressed_texture_etc"_s,
        "WEBGL_compressed_texture_etc1"_s,
        "WEBGL_compressed_texture_pvrtc"_s,
        "WEBGL_compressed_texture_s3tc"_s,
        "WEBGL_compressed_texture_s3tc_srgb"_s,
        "WEBGL_debug_renderer_info"_s,
        "WEBGL_debug_shaders"_s,
        "WEBGL_depth_texture"_s,
        "WEBGL_draw_buffers"_s,
        "WEBGL_lose_context"_s,
        "WEBGL_multi_draw"_s,
        "WEBGL_polygon_mode"_s,
        "WEBGL_provoking_vertex"_s,
        "WEBGL_render_shared_exponent"_s,
        "WEBGL_stencil_texturing"_s,
        "WEBKIT_WEBGL_compressed_texture_pvrtc"_s,
    };
    return set.get();
}

bool isWebGLExtensionInIphoneCanonical(const String& name)
{
    return iphoneCanonicalSet().contains(name);
}

// Per-chip-tier WebGL extension delta (2026-06-22, capture-grounded). The canonical set above is
// the A17 Pro+ (newer-GPU) baseline (derived from iPhone 17 / 16 Pro). Apple's A17 Pro introduced
// desktop-class texture-compression (S3TC/BPTC/RGTC) + float-blend/float-linear; A16 and earlier
// GPUs do NOT expose them. Confirmed via BS /aio: iPhone 14 (A15) / 14 Pro (A16) / 15 (A16) each
// expose 33 webgl1 extensions while iPhone 16 Pro/16 Plus/17/17 Pro Max (A18/A19) expose 39 —
// the delta is exactly these 6 (identical for webgl1 + webgl2, version-independent). So an A16/A15
// archetype must additionally drop these from the canonical set or it over-exposes vs the real chip.
static const HashSet<String>& newerGpuOnlyExtensions()
{
    static NeverDestroyed<HashSet<String>> set = HashSet<String> {
        "EXT_float_blend"_s,
        "EXT_texture_compression_bptc"_s,
        "EXT_texture_compression_rgtc"_s,
        "OES_texture_float_linear"_s,
        "WEBGL_compressed_texture_s3tc"_s,
        "WEBGL_compressed_texture_s3tc_srgb"_s,
    };
    return set.get();
}

// True for archetypes whose GPU is A16 or earlier (no desktop-class GPU extensions): the iPhone 13
// family (A15) + iPhone 14 family (A15/A16, incl 14 Pro/Pro Max) + iPhone 15 / 15 Plus base (A16).
// A17 Pro and later (iphone15pro/15promax, all iphone16/iphone17) keep the full canonical set.
// The confirmed-old set (iphone14/14pro/15) is capture-grounded; iphone13*/14plus/14promax/15plus
// share those exact A15/A16 chips. The launch archetype (iphone17, A19) is new-tier → this is a
// no-op for it; A17 Pro stays at the full set (Apple-spec + = current behavior → no unverified change).
static bool archetypeIsOlderGpuExtensionTier()
{
    static const bool s_older = []() -> bool {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype)
            return false; // no archetype env = launch default iPhone 17 (A19) = newer-GPU tier
        std::string_view a(archetype);
        if (a.find("iphone13") != std::string_view::npos)
            return true; // A15
        if (a.find("iphone14") != std::string_view::npos)
            return true; // A15 (14/14 Plus) / A16 (14 Pro/Pro Max)
        if (a.find("iphone15pro") != std::string_view::npos)
            return false; // iPhone 15 Pro / 15 Pro Max = A17 Pro = newer-GPU tier
        if (a.find("iphone15") != std::string_view::npos)
            return true; // iPhone 15 / 15 Plus = A16
        return false; // iphone16* / iphone17* = A18 / A19 = newer-GPU tier
    }();
    return s_older;
}

void filterWebGLExtensionsToIphoneCanonical(Vector<String>& extensions)
{
    const bool olderTier = archetypeIsOlderGpuExtensionTier();
    extensions.removeAllMatching([olderTier](const String& name) {
        if (!iphoneCanonicalSet().contains(name))
            return true;
        if (olderTier && newerGpuOnlyExtensions().contains(name))
            return true;
        return false;
    });
}

} // namespace Driftstack
} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
