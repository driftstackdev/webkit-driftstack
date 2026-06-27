/*
 * Copyright (C) 2013-2021 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "MapPrototype.h"

#include "BuiltinNames.h"
#include "CachedCallInlines.h"
#include "GetterSetter.h"
#include "InterpreterInlines.h"
#include "JSCInlines.h"
#include "JSMapInlines.h"
#include "JSMapIterator.h"
#include "VMEntryScopeInlines.h"

namespace JSC {

const ClassInfo MapPrototype::s_info = { "Map"_s, &Base::s_info, nullptr, nullptr, CREATE_METHOD_TABLE(MapPrototype) };

static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncClear);
static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncDelete);
static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncGet);
static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncHas);
static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncSet);
static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncGetOrInsert);
static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncGetOrInsertComputed);
static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncValues);
static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncKeys);
JSC_DECLARE_HOST_FUNCTION(mapProtoFuncEntries);

static JSC_DECLARE_HOST_FUNCTION(mapProtoFuncSize);
    
void MapPrototype::finishCreation(VM& vm, JSGlobalObject* globalObject)
{
    Base::finishCreation(vm);
    ASSERT(inherits(info()));

    JSFunction* clearFunc = JSFunction::create(vm, globalObject, 0, vm.propertyNames->clear.string(), mapProtoFuncClear, ImplementationVisibility::Public);
    putDirectWithoutTransition(vm, vm.propertyNames->clear, clearFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().clearPrivateName(), clearFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));

    JSFunction* deleteFunc = JSFunction::create(vm, globalObject, 1, vm.propertyNames->deleteKeyword.string(), mapProtoFuncDelete, ImplementationVisibility::Public, JSMapDeleteIntrinsic);
    putDirectWithoutTransition(vm, vm.propertyNames->deleteKeyword, deleteFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().deletePrivateName(), deleteFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));

    JSFunction* entries = globalObject->mapProtoEntriesFunction();
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().entriesPublicName(), entries, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().entriesPrivateName(), entries, static_cast<unsigned>(PropertyAttribute::DontEnum));

    JSFunction* forEachFunc = JSFunction::create(vm, globalObject, mapPrototypeForEachCodeGenerator(vm), globalObject);
    putDirectWithoutTransition(vm, vm.propertyNames->forEach, forEachFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().forEachPrivateName(), forEachFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));

    JSFunction* getFunc = JSFunction::create(vm, globalObject, 1, vm.propertyNames->get.string(), mapProtoFuncGet, ImplementationVisibility::Public, JSMapGetIntrinsic);
    putDirectWithoutTransition(vm, vm.propertyNames->get, getFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().getPrivateName(), getFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));

    JSFunction* hasFunc = JSFunction::create(vm, globalObject, 1, vm.propertyNames->has.string(), mapProtoFuncHas, ImplementationVisibility::Public, JSMapHasIntrinsic);
    putDirectWithoutTransition(vm, vm.propertyNames->has, hasFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().hasPrivateName(), hasFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));

    JSFunction* keysFunc = JSFunction::create(vm, globalObject, 0, vm.propertyNames->builtinNames().keysPublicName().string(), mapProtoFuncKeys, ImplementationVisibility::Public, JSMapKeysIntrinsic);
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().keysPublicName(), keysFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().keysPrivateName(), keysFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));

    JSFunction* setFunc = JSFunction::create(vm, globalObject, 2, vm.propertyNames->set.string(), mapProtoFuncSet, ImplementationVisibility::Public, JSMapSetIntrinsic);
    putDirectWithoutTransition(vm, vm.propertyNames->set, setFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().setPrivateName(), setFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));

#if PLATFORM(DRIFTSTACK)
    // Wave 29-407.4 (2026-05-20): real iPhone Safari 18.6 (Family A) does
    // NOT expose Map.prototype.getOrInsert / getOrInsertComputed (newer
    // ECMAScript proposal). Skip registration for Family A archetypes.
    //
    // Sweep whag2hew5 (2026-06-26): capture-corrected version floor. These two
    // methods land in Safari 26.2 — real iPhone serves them undefined at 18.6
    // AND at 26.0/26.0.1, function at 26.2+. The skip-list ceiling was safari25_,
    // so safari26_0/safari26_1 fell through and installed (a leak on the 26.0/26.1
    // cohort). EXTENDED to also skip safari26_0/safari26_1 (i.e. skip when <26.2).
    // Launch 26.4 is UNAFFECTED — it stays installed.
    // 2026-06-27 sweep: live getenv, NOT static-cached (silently-inert-gate sweep).
    const bool s_skipMapGetOrInsert = []() {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype)
            return false;
        std::string_view sv(archetype);
        return sv.find("safari17_") != std::string_view::npos
            || sv.find("safari18_") != std::string_view::npos
            || sv.find("safari19_") != std::string_view::npos
            || sv.find("safari20_") != std::string_view::npos
            || sv.find("safari21_") != std::string_view::npos
            || sv.find("safari22_") != std::string_view::npos
            || sv.find("safari23_") != std::string_view::npos
            || sv.find("safari24_") != std::string_view::npos
            || sv.find("safari25_") != std::string_view::npos
            || sv.find("safari26_0") != std::string_view::npos
            || sv.find("safari26_1") != std::string_view::npos;
    }();
    if (!s_skipMapGetOrInsert) {
        JSC_NATIVE_FUNCTION_WITHOUT_TRANSITION("getOrInsert"_s, mapProtoFuncGetOrInsert, static_cast<unsigned>(PropertyAttribute::DontEnum), 2, ImplementationVisibility::Public);
        JSC_NATIVE_FUNCTION_WITHOUT_TRANSITION("getOrInsertComputed"_s, mapProtoFuncGetOrInsertComputed, static_cast<unsigned>(PropertyAttribute::DontEnum), 2, ImplementationVisibility::Public);
    }
#else
    JSC_NATIVE_FUNCTION_WITHOUT_TRANSITION("getOrInsert"_s, mapProtoFuncGetOrInsert, static_cast<unsigned>(PropertyAttribute::DontEnum), 2, ImplementationVisibility::Public);
    JSC_NATIVE_FUNCTION_WITHOUT_TRANSITION("getOrInsertComputed"_s, mapProtoFuncGetOrInsertComputed, static_cast<unsigned>(PropertyAttribute::DontEnum), 2, ImplementationVisibility::Public);
#endif

    JSFunction* sizeGetter = JSFunction::create(vm, globalObject, 0, "get size"_s, mapProtoFuncSize, ImplementationVisibility::Public, JSMapSizeIntrinsic);
    GetterSetter* sizeAccessor = GetterSetter::create(vm, globalObject, sizeGetter, nullptr);
    putDirectNonIndexAccessorWithoutTransition(vm, vm.propertyNames->size, sizeAccessor, PropertyAttribute::DontEnum | PropertyAttribute::Accessor);
    putDirectNonIndexAccessorWithoutTransition(vm, vm.propertyNames->builtinNames().sizePrivateName(), sizeAccessor, PropertyAttribute::DontEnum | PropertyAttribute::Accessor);

    JSFunction* valuesFunc = JSFunction::create(vm, globalObject, 0, vm.propertyNames->builtinNames().valuesPublicName().string(), mapProtoFuncValues, ImplementationVisibility::Public, JSMapValuesIntrinsic);
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().valuesPublicName(), valuesFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));
    putDirectWithoutTransition(vm, vm.propertyNames->builtinNames().valuesPrivateName(), valuesFunc, static_cast<unsigned>(PropertyAttribute::DontEnum));

    putDirectWithoutTransition(vm, vm.propertyNames->iteratorSymbol, entries, static_cast<unsigned>(PropertyAttribute::DontEnum));
    JSC_TO_STRING_TAG_WITHOUT_TRANSITION();

    globalObject->installMapPrototypeWatchpoint(this);
}

ALWAYS_INLINE static JSMap* getMap(JSGlobalObject* globalObject, JSValue thisValue)
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    if (!thisValue.isCell()) [[unlikely]] {
        throwVMError(globalObject, scope, createNotAnObjectError(globalObject, thisValue));
        return nullptr;
    }

    if (auto* map = dynamicDowncast<JSMap>(thisValue.asCell())) [[likely]]
        return map;
    throwTypeError(globalObject, scope, "Map operation called on non-Map object"_s);
    return nullptr;
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncClear, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSMap* map = getMap(globalObject, callFrame->thisValue());
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    scope.release();
    map->clear(globalObject);
    return JSValue::encode(jsUndefined());
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncDelete, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSMap* map = getMap(globalObject, callFrame->thisValue());
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    RELEASE_AND_RETURN(scope, JSValue::encode(jsBoolean(map->remove(globalObject, callFrame->argument(0)))));
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncGet, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSMap* map = getMap(globalObject, callFrame->thisValue());
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    RELEASE_AND_RETURN(scope, JSValue::encode(map->get(globalObject, callFrame->argument(0))));
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncHas, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSMap* map = getMap(globalObject, callFrame->thisValue());
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    RELEASE_AND_RETURN(scope, JSValue::encode(jsBoolean(map->has(globalObject, callFrame->argument(0)))));
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncSet, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSValue thisValue = callFrame->thisValue();
    JSMap* map = getMap(globalObject, thisValue);
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    map->set(globalObject, callFrame->argument(0), callFrame->argument(1));
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));
    return JSValue::encode(thisValue);
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncGetOrInsert, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSMap* map = getMap(globalObject, callFrame->thisValue());
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    JSValue key = callFrame->argument(0);

    RELEASE_AND_RETURN(scope, JSValue::encode(map->getOrInsert(globalObject, key, [&] {
        return callFrame->argument(1);
    })));
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncGetOrInsertComputed, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSMap* map = getMap(globalObject, callFrame->thisValue());
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    map->materializeIfNeeded(globalObject);
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    JSValue key = callFrame->argument(0);

    JSValue valueCallback = callFrame->argument(1);
    if (!valueCallback.isCallable())
        return throwVMTypeError(globalObject, scope, "Map.prototype.getOrInsertComputed requires the callback argument to be callable."_s);

    key = normalizeMapKey(key);
    RELEASE_AND_RETURN(scope, JSValue::encode(map->getOrInsert(globalObject, key, [&] {
        auto callData = JSC::getCallDataInline(valueCallback);
        ASSERT(callData.type != CallData::Type::None);

        if (callData.type == CallData::Type::JS) [[likely]] {
            CachedCall cachedCall(globalObject, uncheckedDowncast<JSFunction>(valueCallback), 1);
            RETURN_IF_EXCEPTION(scope, JSValue());

            return cachedCall.callWithArguments(globalObject, jsUndefined(), key);
        }

        MarkedArgumentBuffer args;
        args.append(key);
        ASSERT(!args.hasOverflowed());

        return call(globalObject, valueCallback, callData, jsUndefined(), args);
    })));
}

inline JSValue createMapIteratorObject(JSGlobalObject* globalObject, CallFrame* callFrame, IterationKind kind)
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSValue thisValue = callFrame->thisValue();
    JSMap* map = getMap(globalObject, thisValue);
    RETURN_IF_EXCEPTION(scope, jsUndefined());

    RELEASE_AND_RETURN(scope, JSMapIterator::create(vm, globalObject->mapIteratorStructure(), map, kind));
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncValues, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    return JSValue::encode(createMapIteratorObject(globalObject, callFrame, IterationKind::Values));
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncKeys, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    return JSValue::encode(createMapIteratorObject(globalObject, callFrame, IterationKind::Keys));
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncEntries, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    return JSValue::encode(createMapIteratorObject(globalObject, callFrame, IterationKind::Entries));
}

JSC_DEFINE_HOST_FUNCTION(mapProtoFuncSize, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    JSMap* map = getMap(globalObject, callFrame->thisValue());
    RETURN_IF_EXCEPTION(scope, JSValue::encode(jsUndefined()));

    return JSValue::encode(jsNumber(map->size()));
}

}
