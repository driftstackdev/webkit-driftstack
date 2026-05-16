/*
 * Copyright (C) 2021 Apple Inc. All rights reserved.
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
#include "StorageManager.h"

#include "ClientOrigin.h"
#include "ContextDestructionObserverInlines.h"
#include "Document.h"
#include "ExceptionOr.h"
#include "FileSystemDirectoryHandle.h"
#include "FileSystemStorageConnection.h"
#include "JSDOMConvertBoolean.h"
#include "JSDOMConvertInterface.h"
#include "JSDOMPromiseDeferred.h"
#include "JSFileSystemDirectoryHandle.h"
#include "JSStorageManager.h"
#include "NavigatorBase.h"
#include "SecurityOrigin.h"
#include "WorkerGlobalScope.h"
#include "WorkerStorageConnection.h"
#include <wtf/TZoneMallocInlines.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(StorageManager);

Ref<StorageManager> StorageManager::create(NavigatorBase& navigator)
{
    return adoptRef(*new StorageManager(navigator));
}

StorageManager::StorageManager(NavigatorBase& navigator)
    : m_navigator(navigator)
{
}

StorageManager::~StorageManager() = default;

struct ConnectionInfo {
    ThreadSafeWeakPtr<StorageConnection> connection;
    ClientOrigin origin;
};

static ExceptionOr<ConnectionInfo> connectionInfo(NavigatorBase* navigator, ExceptionCode exceptionCodeForNoAccess)
{
    if (!navigator)
        return Exception { ExceptionCode::InvalidStateError, "Navigator does not exist"_s };

    RefPtr context = navigator->scriptExecutionContext();
    if (!context)
        return Exception { ExceptionCode::InvalidStateError, "Context is invalid"_s };

    if (context->canAccessResource(ScriptExecutionContext::ResourceType::StorageManager) == ScriptExecutionContext::HasResourceAccess::No)
        return Exception { exceptionCodeForNoAccess, "Context not access storage"_s };

    RefPtr origin = context->securityOrigin();
    ASSERT(origin);

    if (RefPtr document = dynamicDowncast<Document>(*context)) {
        if (RefPtr connection = document->storageConnection())
            return ConnectionInfo { *connection, { document->topOrigin().data(), origin->data() } };

        return Exception { ExceptionCode::InvalidStateError, "Connection is invalid"_s };
    }

    if (RefPtr globalScope = dynamicDowncast<WorkerGlobalScope>(*context))
        return ConnectionInfo { globalScope->storageConnection(), { globalScope->topOrigin().data(), origin->data() } };

    return Exception { ExceptionCode::NotSupportedError };
}

void StorageManager::persisted(DOMPromiseDeferred<IDLBoolean>&& promise)
{
    auto connectionInfoOrException = connectionInfo(protect(m_navigator).get(), ExceptionCode::TypeError);
    if (connectionInfoOrException.hasException())
        return promise.reject(connectionInfoOrException.releaseException());

    auto connectionInfo = connectionInfoOrException.releaseReturnValue();
    connectionInfo.connection.get()->getPersisted(WTF::move(connectionInfo.origin), [promise = WTF::move(promise)](bool persisted) mutable {
        promise.resolve(persisted);
    });
}

void StorageManager::persist(DOMPromiseDeferred<IDLBoolean>&& promise)
{
    auto connectionInfoOrException = connectionInfo(protect(m_navigator).get(), ExceptionCode::TypeError);
    if (connectionInfoOrException.hasException())
        return promise.reject(connectionInfoOrException.releaseException());

    auto connectionInfo = connectionInfoOrException.releaseReturnValue();
    connectionInfo.connection.get()->persist(connectionInfo.origin, [promise = WTF::move(promise)](bool persisted) mutable {
        promise.resolve(persisted);
    });
}

void StorageManager::estimate(DOMPromiseDeferred<IDLDictionary<StorageEstimate>>&& promise)
{
    auto connectionInfoOrException = connectionInfo(protect(m_navigator).get(), ExceptionCode::TypeError);
    if (connectionInfoOrException.hasException())
        return promise.reject(connectionInfoOrException.releaseException());

    auto connectionInfo = connectionInfoOrException.releaseReturnValue();
    connectionInfo.connection.get()->getEstimate(WTF::move(connectionInfo.origin), [promise = WTF::move(promise)](ExceptionOr<StorageEstimate>&& result) mutable {
#if PLATFORM(DRIFTSTACK)
        // V-072 cumulative rig finding: Mac storage.estimate.quota
        // reports ~2x iPhone equivalent (Mac 82GB vs iPhone 41GB on
        // the test machines). The reportedQuota is system-derived
        // from disk free space; halving on Driftstack approximates
        // the iPhone quota tier without needing to track the actual
        // iOS quota algorithm.
        // V-199-D (2026-05-05): retired the V-074 `estimate.usage = 0`
        // override based on a single iPhone capture (2026-05-04T19-24-11Z)
        // reporting usage=8.
        // V-221 (2026-05-06): RE-INSTATED the usage=0 zero-out per
        // V-218 path-a empirical re-capture finding + feedback_population_not_point_match
        // memory rule. Surface is iPhone session-state-dependent:
        //   - 2026-05-04 capture: usage=8 (warmed Safari session)
        //   - 2026-05-05 path-a capture: usage=0 (fresh-cleared Safari session)
        // Mac MiniBrowser returns 8 (always; no real session-state tracking).
        // iPhone in fresh-cleared / cold-cache state returns 0.
        // Driftstack customer sessions = fresh MiniBrowser per session = cleared
        // state by construction. Match iPhone fresh-state: clamp usage=0.
        // V-199-D's "let Mac value pass" framing was wrong (single capture as
        // canonical for runtime-determined surface).
        if (!result.hasException()) {
            auto estimate = result.returnValue();
            // Slice 245.3 (wave 29-246): file 99 S11 + file 110 § Storage
            // quota — archetype-specific quota matching real iPhone disk
            // size class. Env-var override path (DRIFTSTACK_STORAGE_QUOTA_BYTES)
            // takes precedence; falls back to V-072 halving when unset.
            // Same env-routed pattern as Apple Pay (Slice 245.1) until
            // DriftstackArchetypeConfig.h registered for cross-module
            // visibility.
            if (const char* env = getenv("DRIFTSTACK_STORAGE_QUOTA_BYTES")) {
                // Hand-roll uint64 parse to avoid strtoull (Werror=-Wunsafe-buffer-usage-in-libc-call).
                uint64_t override = 0;
                for (const char* p = env; *p >= '0' && *p <= '9'; ++p)
                    override = override * 10 + static_cast<uint64_t>(*p - '0');
                if (override > 0) {
                    estimate.quota = override;
                } else {
                    estimate.quota = estimate.quota / 2;
                }
            } else {
                estimate.quota = estimate.quota / 2;
            }
            estimate.usage = 0;
            promise.resolve(estimate);
            return;
        }
#endif
        promise.settle(WTF::move(result));
    });
}

void StorageManager::fileSystemGetDirectory(DOMPromiseDeferred<IDLInterface<FileSystemDirectoryHandle>>&& promise)
{
    auto connectionInfoOrException = connectionInfo(protect(m_navigator).get(), ExceptionCode::SecurityError);
    if (connectionInfoOrException.hasException())
        return promise.reject(connectionInfoOrException.releaseException());

    auto connectionInfo = connectionInfoOrException.releaseReturnValue();
    connectionInfo.connection.get()->fileSystemGetDirectory(WTF::move(connectionInfo.origin), [promise = WTF::move(promise), weakNavigator = m_navigator](auto&& result) mutable {
        if (result.hasException())
            return promise.reject(result.releaseException());

        auto [identifier, connection] = result.releaseReturnValue();
        RefPtr context = weakNavigator ? weakNavigator->scriptExecutionContext() : nullptr;
        if (!context) {
            connection->closeHandle(identifier);
            return promise.reject(Exception { ExceptionCode::InvalidStateError, "Context has stopped"_s });
        }

        promise.resolve(FileSystemDirectoryHandle::create(*context, { }, identifier, protect(*connection)));
    });
}

} // namespace WebCore
