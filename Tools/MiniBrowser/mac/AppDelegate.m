/*
 * Copyright (C) 2010-2016 Apple Inc. All rights reserved.
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

#import "AppDelegate.h"

#import "ExtensionManagerWindowController.h"
#import "SettingsController.h"
#import "WK1BrowserWindowController.h"
#import "WK2BrowserWindowController.h"
#import <UserNotifications/UNNotificationContent.h>
#import <UserNotifications/UserNotifications.h>
#import <WebKit/WKPreferencesPrivate.h>
#import <WebKit/WKProcessPoolPrivate.h>
#import <WebKit/WKUserContentControllerPrivate.h>
#import <WebKit/WKWebViewConfigurationPrivate.h>
#import <WebKit/WKWebsiteDataStorePrivate.h>
#import <WebKit/WebKit.h>
#import <WebKit/_WKFeature.h>
#import <WebKit/_WKNotificationData.h>
#import <WebKit/_WKProcessPoolConfiguration.h>
#import <WebKit/_WKWebsiteDataStoreConfiguration.h>
#import <notify.h>
#import <objc/runtime.h>
#import <wtf/Platform.h> // for PLATFORM(DRIFTSTACK) below (preprocessor-only, .m-safe)
#if PLATFORM(DRIFTSTACK)
#import "DriftstackWebDriverServer.h"
#import <WebKit/_WKAutomationSession.h>
#import <WebKit/_WKAutomationSessionConfiguration.h>
#import <WebKit/_WKAutomationSessionDelegate.h>
// W1632: SPI implemented in WKWebView.mm; declared here as a category (not WKWebViewPrivate.h) to avoid a
// header-cascade rebuild. Flips an existing web view to controlledByAutomation before handing it to the
// in-process WebDriver session (fixes the W1631 waitForNavigationToComplete hang).
@interface WKWebView (DriftstackAutomation)
- (void)_driftstackSetControlledByAutomation:(BOOL)controlled;
@end
#endif

static const NSString * const kURLArgumentString = @"--url";
static const NSString * const kSiteIsolationArgumentString = @"--force-site-isolation";
static const NSString * const kWebInspectorArgumentString = @"--web-inspector";

static NSString *sTargetURL = nil;

// Force MiniBrowser to run with or without site isolation.
static BOOL sForceSiteIsolationSetting = NO;
static BOOL sShouldEnableSiteIsolation = NO;

static BOOL sOpenWebInspector = NO;

enum {
    WebKit1NewWindowTag = 1,
    WebKit2NewWindowTag = 2,
    WebKit2NewSiteIsolationWindowTag = 5,
    WebKit1NewEditorTag = 3,
    WebKit2NewEditorTag = 4
};

@implementation NSApplication (MiniBrowserApplicationExtensions)

- (BrowserAppDelegate *)browserAppDelegate
{
    return (BrowserAppDelegate *)[self delegate];
}

@end

@interface NSApplication (TouchBar)
@property (getter=isAutomaticCustomizeTouchBarMenuItemEnabled) BOOL automaticCustomizeTouchBarMenuItemEnabled;

@property (readonly, nonatomic) WKWebViewConfiguration *defaultConfiguration;

@end

#if PLATFORM(DRIFTSTACK)
// Driftstack item-9: BrowserAppDelegate doubles as the automation-session delegate,
// handing the in-process WebDriver the existing browser window's web view. The ivar
// retains the session (its own .delegate is weak).
@interface BrowserAppDelegate () <_WKAutomationSessionDelegate> {
    _WKAutomationSession *_driftstackAutomationSession;
}
@end
#endif

@implementation BrowserAppDelegate

- (id)init
{
    self = [super init];
    if (self) {
        _browserWindowControllers = [[NSMutableSet alloc] init];
        _extensionManagerWindowController = [[ExtensionManagerWindowController alloc] init];
        _openNewWindowAtStartup = true;
        [UNUserNotificationCenter currentNotificationCenter].delegate = self;
    }

    return self;
}

static BOOL enabledForFeature(_WKFeature *feature)
{
    if ([[NSUserDefaults standardUserDefaults] objectForKey:feature.key])
        return [[NSUserDefaults standardUserDefaults] boolForKey:feature.key];
    return [feature defaultValue];
}

- (WKWebsiteDataStore *)persistentDataStore
{
    static WKWebsiteDataStore *dataStore;

    if (!dataStore) {
        // W1419 (A3-W237 fix — P0 cross-tenant storage isolation): the fleet spawns ONE fork process per
        // session and the harness sets DRIFTSTACK_DATA_DIR to a per-session directory. Root the ENTIRE
        // WKWebsiteDataStore (cookies, localStorage, IndexedDB, network cache, service workers, general
        // storage, …) under that dir via -initWithDirectory: so each session's persisted state lives on its
        // own disk path = no cross-tenant leak. Without it every session on the host shares the default
        // container store (cookies/localStorage/IndexedDB visible across tenants). Self-gating: only the
        // DRIFTSTACK harness sets the env, so upstream MiniBrowser behaviour is unchanged. (-initWithDirectory:
        // is WK_API_AVAILABLE macos(15.2); the fleet runs macOS 26.x.)
        _WKWebsiteDataStoreConfiguration *configuration;
        const char *driftstackDataDir = getenv("DRIFTSTACK_DATA_DIR");
        if (driftstackDataDir && driftstackDataDir[0]) {
            NSURL *driftstackDataURL = [NSURL fileURLWithPath:[NSString stringWithUTF8String:driftstackDataDir] isDirectory:YES];
            configuration = [[_WKWebsiteDataStoreConfiguration alloc] initWithDirectory:driftstackDataURL];
        } else
            configuration = [[_WKWebsiteDataStoreConfiguration alloc] init];
        configuration.networkCacheSpeculativeValidationEnabled = YES;

        // Push will only function if someone has taken the step to install the test daemon service, or otherwise host it manually.
        [configuration setWebPushMachServiceName:@"org.webkit.webpushtestdaemon.service"];

        if ([configuration respondsToSelector:@selector(setIsDeclarativeWebPushEnabled:)]) {
            _WKFeature *declarativeWebPushFeature = nil;
            NSArray<_WKFeature *> *features = [WKPreferences _features];
            for (_WKFeature *feature in features) {
                if ([feature.key isEqualToString:@"DeclarativeWebPush"]) {
                    declarativeWebPushFeature = feature;
                    break;
                }
            }

            [configuration setIsDeclarativeWebPushEnabled:enabledForFeature(declarativeWebPushFeature)];
        }

        dataStore = [[WKWebsiteDataStore alloc] _initWithConfiguration:configuration];
        dataStore._delegate = self;

        int token;
        notify_register_dispatch("org.webkit.MiniBrowser.clearAllData", &token, dispatch_get_main_queue(), ^(int unusedToken) {
            [dataStore removeDataOfTypes:WKWebsiteDataStore.allWebsiteDataTypes modifiedSince:[NSDate distantPast] completionHandler:^{
                NSLog(@"Removed all website data from default persistent data store.");
            }];
        });

        notify_register_dispatch("org.webkit.MiniBrowser.clearServiceWorkers", &token, dispatch_get_main_queue(), ^(int unusedToken) {
            [dataStore removeDataOfTypes:[NSSet setWithObject:WKWebsiteDataTypeServiceWorkerRegistrations] modifiedSince:[NSDate distantPast] completionHandler:^{
                NSLog(@"Removed all service workers from default persistent data store.");
            }];
        });
    }
    
    return dataStore;
}

- (NSDictionary<NSString *, NSNumber *> *)notificationPermissionsForWebsiteDataStore:(WKWebsiteDataStore *)dataStore
{
    return [[NSUserDefaults standardUserDefaults] dictionaryForKey:@"NotificationPermissions"];
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center didReceiveNotificationResponse:(UNNotificationResponse *)response withCompletionHandler:(void (^)(void))completionHandler
{
    if (![response.actionIdentifier isEqualToString:UNNotificationDefaultActionIdentifier]) {
        NSLog(@"Received UNNotificationResponse that was not for the default action: %@", response.actionIdentifier);
        completionHandler();
        return;
    }

    [self.persistentDataStore _processPersistentNotificationClick:response.notification.request.content.userInfo completionHandler:^(bool result) {
        if (!result)
            NSLog(@"_processPersistentNotificationClick failed");
        completionHandler();
    }];
}

- (void)websiteDataStore:(WKWebsiteDataStore *)dataStore showNotification:(_WKNotificationData *)notificationData
{
    UNMutableNotificationContent *content = [UNMutableNotificationContent new];

    NSLog(@"notificationData.title %@", notificationData.title);
    NSLog(@"notificationData.body  %@", notificationData.body);

    content.title = notificationData.title;
    content.body = notificationData.body;
    if ([notificationData respondsToSelector:@selector(alert)] && notificationData.alert == _WKNotificationAlertEnabled)
        content.sound = [UNNotificationSound defaultSound];

    NSString *notificationSource = notificationData.origin;

    content.subtitle = [NSString stringWithFormat:@"from %@", notificationSource];
    content.userInfo = notificationData.userInfo;

    UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:notificationData.identifier content:content trigger:nil];
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    UNAuthorizationOptions options = UNAuthorizationOptionBadge | UNAuthorizationOptionAlert | UNAuthorizationOptionSound;
    [center requestAuthorizationWithOptions:options completionHandler:^(BOOL granted, NSError *error) {
        if (error) {
            NSLog(@"Error acquiring notification permission: %@", error.description);
            return;
        }
        if (!granted) {
            NSLog(@"Notification permission was denied");
            return;
        }
        [center addNotificationRequest:request withCompletionHandler:^(NSError * _Nullable error) {
            if (error)
                NSLog(@"Failed to add web push notification request: %@", error.debugDescription);
        }];
    }];
}

static NSNumber *_currentBadge;
+ (NSNumber *)currentBadge
{
    return _currentBadge;
}

- (void)websiteDataStore:(WKWebsiteDataStore *)dataStore workerOrigin:(WKSecurityOrigin *)workerOrigin updatedAppBadge:(NSNumber *)badge
{
    _currentBadge = badge;

    for (BrowserWindowController *controller in _browserWindowControllers)
        [controller updateTitleForBadgeChange];
}

- (void)_processPendingPushMessages
{
    [[self persistentDataStore] _getPendingPushMessages:^(NSArray<NSDictionary *> *pendingPushMessages) {
        for (NSDictionary *message in pendingPushMessages) {
            [[self persistentDataStore] _processPushMessage:message completionHandler:^(bool success) {
            }];
        }
    }];
}

- (void)_handleURLEvent:(NSAppleEventDescriptor *)event withReplyEvent:(NSAppleEventDescriptor *)replyEvent
{
    NSAppleEventDescriptor *directAEDesc = [event paramDescriptorForKeyword:keyDirectObject];
    NSURL *url = [NSURL URLWithString:[directAEDesc stringValue]];
    if ([[url scheme] isEqualToString:@"x-webkit-app-launch"])
        [self _processPendingPushMessages];
}

- (void)awakeFromNib
{
    _settingsController = [[SettingsController alloc] initWithMenu:_settingsMenu];

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if ([_settingsController usesGameControllerFramework])
        [WKProcessPool _forceGameControllerFramework];
#pragma clang diagnostic pop

    if ([NSApp respondsToSelector:@selector(setAutomaticCustomizeTouchBarMenuItemEnabled:)])
        [NSApp setAutomaticCustomizeTouchBarMenuItemEnabled:YES];

    [[NSAppleEventManager sharedAppleEventManager] setEventHandler:self
                                                       andSelector:@selector(_handleURLEvent:withReplyEvent:)
                                                     forEventClass:kInternetEventClass
                                                        andEventID:(AEEventID)kAEGetURL];
    [[NSAppleEventManager sharedAppleEventManager] setEventHandler:self
                                                       andSelector:@selector(_handleURLEvent:withReplyEvent:)
                                                     forEventClass:'WWW!'
                                                        andEventID:'OURL'];
    [self _parseArguments];
}

- (void)_parseArguments
{
    NSArray *args = [[NSProcessInfo processInfo] arguments];

    const NSUInteger targetURLIndex = [args indexOfObject:kURLArgumentString];
    if (targetURLIndex != NSNotFound && targetURLIndex + 1 < [args count])
        sTargetURL = [args objectAtIndex:targetURLIndex + 1];

    const NSUInteger siteIsolationIndex = [args indexOfObject:kSiteIsolationArgumentString];
    sForceSiteIsolationSetting = (siteIsolationIndex != NSNotFound && siteIsolationIndex + 1 < [args count]);
    if (sForceSiteIsolationSetting) {
        sShouldEnableSiteIsolation = [[args objectAtIndex:siteIsolationIndex + 1] isEqualToString: @"YES"];
        if (sShouldEnableSiteIsolation)
            NSLog(@"Force enabling Site Isolation.");
        else
            NSLog(@"Force disabling Site Isolation.");
    }

    const NSUInteger webInspectorIndex = [args indexOfObject:kWebInspectorArgumentString];
    sOpenWebInspector = (webInspectorIndex != NSNotFound);
}

- (WKWebViewConfiguration *)defaultConfiguration
{
    static WKWebViewConfiguration *configuration;

    if (!configuration) {
        configuration = [[WKWebViewConfiguration alloc] init];
        configuration.websiteDataStore = [self persistentDataStore];

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        _WKProcessPoolConfiguration *processConfiguration = [[_WKProcessPoolConfiguration alloc] init];
        if (_settingsController.perWindowWebProcessesDisabled)
            processConfiguration.usesSingleWebProcess = YES;
        else
            processConfiguration.usesWebProcessCache = YES;

        configuration.processPool = [[WKProcessPool alloc] _initWithConfiguration:processConfiguration];
#pragma clang diagnostic pop

        NSArray<_WKFeature *> *features = [WKPreferences _features];
        for (_WKFeature *feature in features) {
            if ([feature.key isEqualToString:@"MediaDevicesEnabled"])
                continue;

            [configuration.preferences _setEnabled:enabledForFeature(feature) forFeature:feature];
        }

        configuration.preferences.elementFullscreenEnabled = YES;
        configuration.preferences._allowsPictureInPictureMediaPlayback = YES;
        configuration.preferences._developerExtrasEnabled = YES;
        configuration.preferences._accessibilityIsolatedTreeEnabled = YES;
        configuration.preferences._logsPageMessagesToSystemConsoleEnabled = YES;
        // Driftstack fork — iPhone archetype does NOT expose
        // window.Notification or related Push APIs in non-PWA contexts.
        // The upstream MiniBrowser developer-convenience force-enables of
        // _pushAPIEnabled / _notificationsEnabled / _notificationEventEnabled /
        // _appBadgeEnabled override the wave-2-2-prefs YAML default and break
        // archetype matching. Removed in the Driftstack fork (this build is
        // always Driftstack; force-enables not needed since dev experience
        // here is archetype-matching, not extra-permissive).

        if (sForceSiteIsolationSetting)
            configuration.preferences._siteIsolationEnabled = sShouldEnableSiteIsolation;

        // Wave 29-499.282 — DRIFTSTACK_BEHAVIORAL_SIM=1 injects a user script
        // at document-start that synthesizes mouse activity throughout the
        // page's lifetime. Foundation for reCAPTCHA invisible behavioral
        // scoring; standalone synthetic events have isTrusted=false which
        // reCAPTCHA may detect, but baseline coverage is better than nothing.
        // Future: WebKit-level native event injection via EventDispatcher for
        // isTrusted=true.
        const char* behavioralSim = getenv("DRIFTSTACK_BEHAVIORAL_SIM");
        if (behavioralSim && behavioralSim[0] == '1') {
            NSString *jsSrc = @"(function(){\n"
                "  if (window.__driftstackBehavioralSim) return;\n"
                "  window.__driftstackBehavioralSim = true;\n"
                "  let mmCount = 0;\n"
                "  const fire = () => {\n"
                "    const x = Math.random() * (window.innerWidth || 402);\n"
                "    const y = Math.random() * (window.innerHeight || 874);\n"
                "    document.dispatchEvent(new MouseEvent('mousemove', {\n"
                "      clientX: x, clientY: y, screenX: x, screenY: y,\n"
                "      bubbles: true, cancelable: true, view: window\n"
                "    }));\n"
                "    mmCount++;\n"
                "    if (mmCount < 200) setTimeout(fire, 50 + Math.random() * 150);\n"
                "  };\n"
                "  setTimeout(fire, 500);\n"
                "  // also occasional scroll\n"
                "  setTimeout(() => { for (let i = 0; i < 3; i++) setTimeout(() => window.scrollBy(0, 50 + Math.random() * 100), i * 800); }, 2000);\n"
                "})();";
            WKUserScript *script = [[WKUserScript alloc] initWithSource:jsSrc
                injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                forMainFrameOnly:NO];
            [configuration.userContentController addUserScript:script];
            NSLog(@"[Driftstack-EG-WK-Wave29-499.282] BehavioralSim user script injected (mousemove + scroll at documentStart)");
        }
    }

    configuration.suppressesIncrementalRendering = _settingsController.incrementalRenderingSuppressed;
    configuration.websiteDataStore._resourceLoadStatisticsEnabled = _settingsController.resourceLoadStatisticsEnabled;
    configuration._attachmentElementEnabled = _settingsController.attachmentElementEnabled != AttachmentElementEnabledStateDisabled ? YES : NO;
    configuration._attachmentWideLayoutEnabled = _settingsController.attachmentElementEnabled == AttachmentElementEnabledStateWideLayoutEnabled ? YES : NO;
    configuration._allowUniversalAccessFromFileURLs = _settingsController.allowUniversalAccessFromFileURLs;

    return configuration;
}

- (WKWebViewConfiguration *)defaultConfigurationForcingSiteIsolation:(BOOL)forceSiteIsolation
{
    if (!forceSiteIsolation)
        return self.defaultConfiguration;

    WKWebViewConfiguration *configuration = self.defaultConfiguration;
    if (configuration.preferences._siteIsolationEnabled)
        return configuration;

    configuration = configuration.copy;
    configuration.preferences = configuration.preferences.copy;
    configuration.preferences._siteIsolationEnabled = YES;
    return configuration;
}

- (WKPreferences *)defaultPreferences
{
    return self.defaultConfiguration.preferences;
}

- (BrowserWindowController *)createBrowserWindowController:(id)sender
{
    BrowserWindowController *controller = nil;
    BOOL useWebKit2 = NO;
    BOOL makeEditable = NO;
    BOOL forcesSiteIsolation = NO;

    BOOL hasNSIntegerTag = NO;
    if ([sender respondsToSelector:@selector(tag)]) {
        Method tagMethod = class_getInstanceMethod([sender class], @selector(tag));
        char *tagReturnType = method_copyReturnType(tagMethod);
        if (!strcmp(tagReturnType, @encode(NSInteger)))
            hasNSIntegerTag = YES;
        free(tagReturnType);
    }

    if (!hasNSIntegerTag) {
        useWebKit2 = _settingsController.useWebKit2ByDefault;
        makeEditable = _settingsController.createEditorByDefault;
    } else {
        NSInteger senderTag = (NSInteger)[sender performSelector:@selector(tag)];
        useWebKit2 = senderTag == WebKit2NewWindowTag || senderTag == WebKit2NewEditorTag || senderTag == WebKit2NewSiteIsolationWindowTag;
        forcesSiteIsolation = senderTag == WebKit2NewSiteIsolationWindowTag;
        makeEditable = senderTag == WebKit1NewEditorTag || senderTag == WebKit2NewEditorTag;
    }

    if (!useWebKit2)
        controller = [[WK1BrowserWindowController alloc] initWithWindowNibName:@"BrowserWindow"];
    else
        controller = [[WK2BrowserWindowController alloc] initWithConfiguration:[self defaultConfigurationForcingSiteIsolation:forcesSiteIsolation]];

    if (makeEditable)
        controller.editable = YES;

    if (!controller)
        return nil;

    [_browserWindowControllers addObject:controller];

    return controller;
}

- (NSString *)targetURL
{
    NSString *url = sTargetURL;
    sTargetURL = nil;

    if (!url || [url isEqualToString:@""]) {
        url = _settingsController.defaultURL;
#if PLATFORM(DRIFTSTACK)
        // W2763: the harness sets the per-session start URL via the DRIFTSTACK_INITIAL_URL ENV var. NOT a
        // launch arg — a bare positional URL is ignored by _parseArguments (only `--url` is read), and the
        // `--url` flag itself broke the WD-server startup (W2757 → reverted W2758); a post-load WD navigate
        // (W2759) proved unreliable in the field (the fork stayed on the webkit.org default — verified via
        // egress: zero requests to the dispatched URL). Load the dispatched URL DIRECTLY here, at startup,
        // through this SAME proven defaultURL path that already loads any page — so it renders the customer's
        // Start URL instead of webkit.org, with no flash, no navigate race, and no WD-startup interaction.
        const char *driftstackInitialURL = getenv("DRIFTSTACK_INITIAL_URL");
        if (driftstackInitialURL && driftstackInitialURL[0])
            url = [NSString stringWithUTF8String:driftstackInitialURL];
#endif
    }

    return url;
}

- (IBAction)newWindow:(id)sender
{
    BrowserWindowController *controller = [self createBrowserWindowController:sender];
    if (!controller)
        return;

    [[controller window] makeKeyAndOrderFront:sender];
    [controller loadURLString:[self targetURL]];

    if (sOpenWebInspector)
        [controller showHideWebInspector:sender];
}

- (IBAction)newPrivateWindow:(id)sender
{
    WKWebViewConfiguration *privateConfiguraton = [self.defaultConfiguration copy];
    privateConfiguraton.websiteDataStore = [WKWebsiteDataStore nonPersistentDataStore];

    BrowserWindowController *controller = [[WK2BrowserWindowController alloc] initWithConfiguration:privateConfiguraton];

    [[controller window] makeKeyAndOrderFront:sender];
    [_browserWindowControllers addObject:controller];

    [controller loadURLString:[self targetURL]];

    if (sOpenWebInspector)
        [controller showHideWebInspector:sender];
}

- (IBAction)newEditorWindow:(id)sender
{
    BrowserWindowController *controller = [self createBrowserWindowController:sender];
    if (!controller)
        return;

    [[controller window] makeKeyAndOrderFront:sender];
    [controller loadHTMLString:@"<html><body></body></html>"];
}

- (IBAction)newTab:(id)sender
{
    NSWindow *keyWindow = [NSApp keyWindow];
    BrowserWindowController *currentController = nil;

    if ([keyWindow.delegate isKindOfClass:[BrowserWindowController class]])
        currentController = (BrowserWindowController *)keyWindow.delegate;

    if (!currentController) {
        // No current window, create a new window instead
        [self newWindow:sender];
        return;
    }

    // Create new controller matching current window's type (WK1 vs WK2)
    BrowserWindowController *newController = nil;
    if ([currentController isKindOfClass:[WK2BrowserWindowController class]]) {
        WK2BrowserWindowController *wk2Controller = (WK2BrowserWindowController *)currentController;
        // Copy configuration from current window (preserves private browsing, site isolation, etc.)
        WKWebViewConfiguration *config = [wk2Controller.webView.configuration copy];
        newController = [[WK2BrowserWindowController alloc] initWithConfiguration:config];
    } else
        newController = [[WK1BrowserWindowController alloc] initWithWindowNibName:@"BrowserWindow"];

    if (!newController)
        return;

    [_browserWindowControllers addObject:newController];

    // Add as tab to current window
    [keyWindow addTabbedWindow:[newController window] ordered:NSWindowAbove];
    [[newController window] makeKeyAndOrderFront:sender];
    [newController loadURLString:[self targetURL]];
}

- (void)didCreateBrowserWindowController:(BrowserWindowController *)controller
{
    [_browserWindowControllers addObject:controller];
}

- (void)browserWindowWillClose:(NSWindow *)window
{
    [_browserWindowControllers removeObject:window.windowController];
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    WebHistory *webHistory = [[WebHistory alloc] init];
    [WebHistory setOptionalSharedHistory:webHistory];

    [self _updateNewWindowKeyEquivalents];

    if (!_openNewWindowAtStartup)
        return;

    if (_settingsController.createEditorByDefault)
        [self newEditorWindow:self];
    else
        [self newWindow:self];

#if PLATFORM(DRIFTSTACK)
    [self _driftstackSetUpWebDriverIfRequested];
#endif
}

#if PLATFORM(DRIFTSTACK)
// Driftstack item-9: on --enable-webdriver=<sessionId>, create + install an
// _WKAutomationSession on the shared process pool and start the in-process WebDriver
// server (writes /tmp/driftstack-webdriver-<sessionId>.port). The harness then drives
// every intent over W3C WebDriver against this MiniBrowser.
- (void)_driftstackSetUpWebDriverIfRequested
{
    NSString *prefix = @"--enable-webdriver=";
    NSString *sessionID = nil;
    for (NSString *arg in [[NSProcessInfo processInfo] arguments]) {
        if ([arg hasPrefix:prefix]) {
            sessionID = [arg substringFromIndex:prefix.length];
            break;
        }
    }
    if (!sessionID.length)
        return;

    // Ensure a window exists for the automation session to drive.
    if (![self frontmostBrowserWindowController])
        [self newWindow:self];

    // WKProcessPool is deprecated for multi-pool use ("no longer has any effect"), but the single
    // default pool's `_setAutomationSession:` SPI is still the canonical automation-wiring path —
    // mirroring upstream MiniBrowser's own deprecation-suppressed WKProcessPool SPI usage (e.g. :259).
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    WKProcessPool *processPool = self.defaultConfiguration.processPool;
#pragma clang diagnostic pop
    if (!processPool) {
        NSLog(@"[Driftstack] WebDriver: no process pool; cannot start automation");
        return;
    }

    _WKAutomationSessionConfiguration *configuration = [[_WKAutomationSessionConfiguration alloc] init];
    _driftstackAutomationSession = [[_WKAutomationSession alloc] initWithConfiguration:configuration];
    _driftstackAutomationSession.delegate = self;
    _driftstackAutomationSession.sessionIdentifier = sessionID;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [processPool _setAutomationSession:_driftstackAutomationSession];
#pragma clang diagnostic pop

    DriftstackStartWebDriverServer(sessionID, _driftstackAutomationSession);
}

#pragma mark _WKAutomationSessionDelegate (item-9)

- (void)_automationSession:(_WKAutomationSession *)automationSession requestNewWebViewWithOptions:(_WKAutomationSessionBrowsingContextOptions)options completionHandler:(void(^)(WKWebView *))completionHandler
{
    // Hand back the existing MiniBrowser window's web view (single in-process session).
    BrowserWindowController *controller = [self frontmostBrowserWindowController];
    if (![controller isKindOfClass:[WK2BrowserWindowController class]]) {
        [self newWindow:self];
        controller = [self frontmostBrowserWindowController];
    }
    if ([controller isKindOfClass:[WK2BrowserWindowController class]]) {
        WKWebView *automationWebView = [(WK2BrowserWindowController *)controller webView];
        [automationWebView _driftstackSetControlledByAutomation:YES]; // W1632: fix navigationOccurredForFrame
        completionHandler(automationWebView);
    } else
        completionHandler(nil);
}
#endif // PLATFORM(DRIFTSTACK)

- (BrowserWindowController *)frontmostBrowserWindowController
{
    for (NSWindow* window in [NSApp windows]) {
        id delegate = [window delegate];

        if (![delegate isKindOfClass:[BrowserWindowController class]])
            continue;

        BrowserWindowController *controller = (BrowserWindowController *)delegate;
        assert([_browserWindowControllers containsObject:controller]);
        return controller;
    }

    return nil;
}

- (BOOL)application:(NSApplication *)theApplication openFile:(NSString *)filename
{
    BrowserWindowController *controller = [self createBrowserWindowController:nil];
    if (!controller)
        return NO;

    NSURL *url = [NSURL URLWithString:filename];
    if (!url || !url.scheme)
        url = [NSURL fileURLWithPath:filename];

    [controller.window makeKeyAndOrderFront:self];
    [controller loadURLString:url.absoluteString];

    if (sOpenWebInspector)
        [controller showHideWebInspector:nil];

    _openNewWindowAtStartup = false;
    return YES;
}

- (IBAction)openDocument:(id)sender
{
    BrowserWindowController *browserWindowController = [self frontmostBrowserWindowController];

    if (browserWindowController) {
        NSOpenPanel *openPanel = [NSOpenPanel openPanel];
        [openPanel beginSheetModalForWindow:browserWindowController.window completionHandler:^(NSInteger result) {
            if (result != NSModalResponseOK)
                return;

            NSURL *url = [openPanel.URLs objectAtIndex:0];
            [browserWindowController loadURLString:[url absoluteString]];

            if (sOpenWebInspector)
                [browserWindowController showHideWebInspector:sender];
        }];
        return;
    }

    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel beginWithCompletionHandler:^(NSInteger result) {
        if (result != NSModalResponseOK)
            return;

        BrowserWindowController *controller = [self createBrowserWindowController:nil];
        [controller.window makeKeyAndOrderFront:self];

        NSURL *url = [openPanel.URLs objectAtIndex:0];
        [controller loadURLString:[url absoluteString]];

        if (sOpenWebInspector)
            [controller showHideWebInspector:sender];
    }];
}

- (void)didChangeSettings
{
    [self _updateNewWindowKeyEquivalents];

    // Let all of the BrowserWindowControllers know that a setting changed, so they can attempt to dynamically update.
    for (BrowserWindowController *browserWindowController in _browserWindowControllers)
        [browserWindowController didChangeSettings];
}

- (void)_updateNewWindowKeyEquivalents
{
    NSEventModifierFlags webKit1Flags = _settingsController.useWebKit2ByDefault ? NSEventModifierFlagOption : 0;
    NSEventModifierFlags webKit2Flags = _settingsController.useWebKit2ByDefault ? 0 : NSEventModifierFlagOption;
    NSEventModifierFlags siteIsolationWebKit2Flags = webKit2Flags | NSEventModifierFlagControl;

    NSString *normalWindowEquivalent = _settingsController.createEditorByDefault ? @"N" : @"n";
    NSString *editorEquivalent = _settingsController.createEditorByDefault ? @"n" : @"N";

    _newWebKit1WindowItem.keyEquivalentModifierMask = NSEventModifierFlagCommand | webKit1Flags;
    _newWebKit2WindowItem.keyEquivalentModifierMask = NSEventModifierFlagCommand | webKit2Flags;
    _newWebKit2SiteIsolateWindowItem.keyEquivalentModifierMask = NSEventModifierFlagCommand | siteIsolationWebKit2Flags;
    _newWebKit1EditorItem.keyEquivalentModifierMask = NSEventModifierFlagCommand | webKit1Flags;
    _newWebKit2EditorItem.keyEquivalentModifierMask = NSEventModifierFlagCommand | webKit2Flags;

    _newWebKit1WindowItem.keyEquivalent = normalWindowEquivalent;
    _newWebKit2WindowItem.keyEquivalent = normalWindowEquivalent;
    _newWebKit2SiteIsolateWindowItem.keyEquivalent = normalWindowEquivalent;
    _newWebKit1EditorItem.keyEquivalent = editorEquivalent;
    _newWebKit2EditorItem.keyEquivalent = editorEquivalent;
}

- (IBAction)showExtensionsManager:(id)sender
{
    [_extensionManagerWindowController showWindow:sender];
}

- (WKUserContentController *)userContentContoller
{
    return self.defaultConfiguration.userContentController;
}

- (IBAction)fetchDefaultStoreWebsiteData:(id)sender
{
    [[self persistentDataStore] fetchDataRecordsOfTypes:[WKWebsiteDataStore allWebsiteDataTypes] completionHandler:^(NSArray *websiteDataRecords) {
        NSLog(@"did fetch default store website data %@.", websiteDataRecords);
    }];
}

- (IBAction)fetchAndClearDefaultStoreWebsiteData:(id)sender
{
    [[self persistentDataStore] fetchDataRecordsOfTypes:[WKWebsiteDataStore allWebsiteDataTypes] completionHandler:^(NSArray *websiteDataRecords) {
        [[self persistentDataStore] removeDataOfTypes:[WKWebsiteDataStore allWebsiteDataTypes] forDataRecords:websiteDataRecords completionHandler:^{
            [[self persistentDataStore] fetchDataRecordsOfTypes:[WKWebsiteDataStore allWebsiteDataTypes] completionHandler:^(NSArray *websiteDataRecords) {
                NSLog(@"did clear default store website data, after clearing data is %@.", websiteDataRecords);
            }];
        }];
    }];
}

- (IBAction)clearDefaultStoreWebsiteData:(id)sender
{
    [[self persistentDataStore] removeDataOfTypes:[WKWebsiteDataStore allWebsiteDataTypes] modifiedSince:[NSDate distantPast] completionHandler:^{
        NSLog(@"Did clear default store website data.");
    }];
}

static const char* windowProxyPropertyDescription(WKWindowProxyProperty property)
{
    switch (property) {
    case WKWindowProxyPropertyInitialOpen:
        return "initialOpen";
    case WKWindowProxyPropertyClosed:
        return "closed";
    case WKWindowProxyPropertyPostMessage:
        return "postMessage";
    case WKWindowProxyPropertyOther:
        return "other";
    }
    return "other";
}

- (void)websiteDataStore:(WKWebsiteDataStore *)dataStore domain:(NSString *)registrableDomain didOpenDomainViaWindowOpen:(NSString *)openedRegistrableDomain withProperty:(WKWindowProxyProperty)property directly:(BOOL)directly
{
    NSLog(@"MiniBrowser detected cross-tab WindowProxy access between parent origin %@ and child origin %@ via property %s (directlyAccessed = %d)", registrableDomain, openedRegistrableDomain, windowProxyPropertyDescription(property), directly);
}

@end
