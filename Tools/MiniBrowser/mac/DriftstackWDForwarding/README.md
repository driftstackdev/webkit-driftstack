# DriftstackWDForwarding — item-9 drive-bridge header shim

The in-process WebDriver server compiled into MiniBrowser (item-9) builds the socket
`HTTPServer` + `SessionHost` with `USE_INSPECTOR_SOCKET_SERVER=1`. Those headers include
`<JavaScriptCore/RemoteInspectorSocketEndpoint.h>` / `<JavaScriptCore/RemoteInspectorConnectionClient.h>`,
which live in `Source/JavaScriptCore/inspector/remote/socket/` but are NOT exported into the
cocoa JavaScriptCore.framework (cocoa builds the XPC remote inspector, not the socket one).

The `JavaScriptCore` symlink here points at that socket source dir so the angle-bracket
`<JavaScriptCore/...>` includes resolve, and the headers' own quote-include siblings
(`"RemoteInspectorSocket.h"`, etc.) resolve in the same real dir. `MiniBrowser.xcconfig` adds
this dir to `HEADER_SEARCH_PATHS`. Non-socket `<JavaScriptCore/...>` headers still resolve from
the framework (no name overlap with the socket dir).
