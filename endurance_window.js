// The Endurance - control window (JXA + WebKit, nothing to install).
// Usage: osascript -l JavaScript endurance_window.js <icon.icns> <launcher> <window.html> <work dir>
// The page talks to this script through its title ("CMD:{json}"); commands run as `launcher --do ...`
// and the status comes from `launcher --status`, both through files in the work dir (never blocking the window).
ObjC.import('Cocoa');
ObjC.import('WebKit');

var W = {};
var LAUNCHER = '', WORK = '', pending = {}, statusAsked = 0, statusRunning = false, seq = 0, TAB = 'home';
var stateAsked = 0, stateRunning = false;   // fast refresh of the monitor state (home tab): one curl per second

// zero-argument methods: JXA may or may not call them on access, so call only if we got a function back
function inv(o, name) { var f = o[name]; if (typeof f === 'function') { return f.call(o); } return f; }
function noop(result, error) {}
function log(m) { try { console.log(m); } catch (e) {} }

function fileText(path) {
  var s = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, $());
  return s ? ObjC.unwrap(s) : null;
}
function exists(path) { return $.NSFileManager.defaultManager.fileExistsAtPath(path); }
function remove(path) { $.NSFileManager.defaultManager.removeItemAtPathError(path, $()); }
function sh(cmd) { $.NSTask.launchedTaskWithLaunchPathArguments('/bin/bash', ['-c', cmd]); }
function q(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
function push(fn, json) {
  W.web.evaluateJavaScriptCompletionHandler(fn + '(JSON.parse(' + JSON.stringify(json) + '))', noop);
}

// Close hides the whole app (like Cmd+H): it stays in the Dock, the monitor keeps running, and a click on the Dock icon
// brings the window back through macOS itself (it does not depend on this script answering). On top of that:
//  - the 1 s "slow" timer notices a window that should be visible but is not and shows it again;
//  - the page is reloaded if macOS killed its web process while the app was hidden.
function appObj() { return $.NSApplication.sharedApplication; }
function appHidden() { try { return !!inv(appObj(), 'isHidden'); } catch (e) { return false; } }
function winVisible() { try { return !!inv(W.win, 'isVisible'); } catch (e) { return true; } }
function winMini() { try { return !!inv(W.win, 'isMiniaturized'); } catch (e) { return false; } }
function setTimer(sec) {
  if (W.sec === sec) { return; }
  try { if (W.timer) { W.timer.invalidate(); } } catch (e) {}
  W.timer = $.NSTimer.scheduledTimerWithTimeIntervalTargetSelectorUserInfoRepeats(sec, W.delegate, 'tick:', null, true);
  W.sec = sec;
}
function reloadWeb() {
  try {
    var src = fileText(W.html) || '<body style="background:#000;color:#ff8a00">window.html not found</body>';
    W.web.loadHTMLStringBaseURL(src, $.NSURL.fileURLWithPath(W.html));
    TAB = 'home'; statusAsked = 0; stateAsked = 0; statusRunning = false; stateRunning = false;
  } catch (e) { log('reload failed: ' + e); }
}
function showWin() {
  try {
    var app = appObj();
    if (appHidden()) { app.unhide(null); }
    if (W.win) {
      if (winMini()) { W.win.deminiaturize(null); }
      else if (!winVisible()) { W.win.makeKeyAndOrderFront(null); }
    }
    app.activateIgnoringOtherApps(true);
    statusAsked = 0; stateAsked = 0;
    setTimer(0.25);
  } catch (e) { log('showWin: ' + e); }
}
function hideWin() { try { appObj().hide(null); setTimer(1.0); } catch (e) {} }

function askState() {
  stateRunning = true; stateAsked = Date.now();
  var out = WORK + '/state.json';
  remove(out);
  $.NSTask.launchedTaskWithLaunchPathArguments('/usr/bin/curl', ['-s', '--max-time', '1', '-o', out, 'http://127.0.0.1:8080/state']);
}

function askStatus() {
  statusRunning = true;
  var out = WORK + '/status.json';
  sh(q(LAUNCHER) + ' --status ' + q(TAB) + ' > ' + q(out + '.tmp') + ' 2>/dev/null; mv ' + q(out + '.tmp') + ' ' + q(out));
}

function runCommand(c) {
  if (c.name === 'tab') { TAB = String((c.args || ['home'])[0]).replace(/[^a-z]/g, '') || 'home'; statusAsked = 0; return; }
  if (c.name === 'hide') { hideWin(); return; }
  if (c.name === 'quit') {
    // confirmed in the window: quit for real (the launcher then stops the monitor). If the app is stuck, kill it after 5 s.
    allowQuit();
    $.NSApplication.sharedApplication.terminate(null);
    return;
  }
  seq += 1;
  var out = WORK + '/do-' + seq + '.json';
  pending[seq] = out;
  var args = (c.args || []).map(function (a) { return q(a); }).join(' ');
  sh(q(LAUNCHER) + ' --do ' + q(c.name) + ' ' + args + ' > ' + q(out + '.tmp') + ' 2>/dev/null; mv ' + q(out + '.tmp') + ' ' + q(out));
}

// Cmd+Q, the Dock menu and the close button ask for confirmation in the window before quitting.
// A second Cmd+Q within 4 seconds quits at once (in case the window cannot answer); log out / shut down are never blocked.
function allowQuit() {   // from here on the quit goes through; if the process is still alive 5 s later, it is killed (never left running)
  if (W.killArmed) { W.okToQuit = true; return; }
  W.okToQuit = true; W.killArmed = true;
  try {
    var mypid = String(Number(inv($.NSProcessInfo.processInfo, 'processIdentifier')));
    if (/^[0-9]+$/.test(mypid) && mypid !== '0') { sh('(sleep 5; kill -9 ' + mypid + ') >/dev/null 2>&1 &'); }
  } catch (e) {}
}
function askQuit() {
  if (W.okToQuit) { return 1; }
  var now = Date.now();
  if (W.askedAt && now - W.askedAt < 4000) { allowQuit(); return 1; }
  W.askedAt = now;
  try { $.NSApplication.sharedApplication.activateIgnoringOtherApps(true); W.win.makeKeyAndOrderFront(null); } catch (e) {}
  try { W.web.evaluateJavaScriptCompletionHandler('window.dpAskQuit&&window.dpAskQuit()', noop); } catch (e) {}
  return 0;
}

// Quit from the Dock menu (right-click > Quit) or from AppleScript: it arrives as an Apple event 'aevt'/'quit'. It is handled here
// explicitly and answered with a native confirmation, which shows up even when the window is hidden or the web view is asleep.
function dockQuit() {
  if (W.okToQuit) { try { $.NSApplication.sharedApplication.terminate(null); } catch (e) {} return; }
  if (W.inQuitAlert) { allowQuit(); try { $.NSApplication.sharedApplication.terminate(null); } catch (e) {} return; }   // asked twice: quit now
  W.inQuitAlert = true;
  try {
    var app = $.NSApplication.sharedApplication;
    try { app.unhide(null); } catch (e) {}
    try { W.win.deminiaturize(null); } catch (e) {}
    try { W.win.makeKeyAndOrderFront(null); } catch (e) {}
    try { app.activateIgnoringOtherApps(true); } catch (e) {}
    var al = $.NSAlert.alloc.init;
    al.messageText = 'Quit The Endurance?';
    al.informativeText = 'Quitting stops the monitor.';
    al.addButtonWithTitle('Quit');
    al.addButtonWithTitle('Cancel');
    var r = Number(al.runModal);
    W.inQuitAlert = false;
    if (r === 1000) { allowQuit(); app.terminate(null); }
  } catch (e) { W.inQuitAlert = false; log('dock quit: ' + e); allowQuit(); try { $.NSApplication.sharedApplication.terminate(null); } catch (e2) {} }
}

var DP_METHODS = {
    'applicationShouldTerminateAfterLastWindowClosed:': {
      types: ['bool', ['id']],
      implementation: function (app) { return false; }
    },
    'applicationShouldHandleReopen:hasVisibleWindows:': {
      types: ['bool', ['id', 'bool']],
      implementation: function (app, flag) { showWin(); return true; }
    },
    'applicationDidBecomeActive:': {
      types: ['void', ['id']],
      implementation: function (n) { showWin(); }
    },
    'applicationDidUnhide:': {
      types: ['void', ['id']],
      implementation: function (n) { showWin(); }
    },
    'webViewWebContentProcessDidTerminate:': {
      types: ['void', ['id']],
      implementation: function (v) { reloadWeb(); }
    },
    'dpQuitEvent:withReplyEvent:': {
      types: ['void', ['id', 'id']],
      implementation: function (ev, reply) { dockQuit(); }
    },
    'tick:': {
      types: ['void', ['id']],
      implementation: function (timer) {
        try {
          if (appHidden()) { setTimer(1.0); return; }             // app hidden (Close): nothing to do, slow timer
          if (!winVisible()) {
            if (winMini()) { setTimer(1.0); return; }             // minimized on purpose
            showWin();                                            // should be visible but is not: show it again
          }
          setTimer(0.25);
          // 1. commands coming from the page
          var title = ObjC.unwrap(W.web.title) || '';
          if (title.indexOf('CMD:') === 0) {
            W.web.evaluateJavaScriptCompletionHandler("document.title='DP'", noop);
            runCommand(JSON.parse(title.substring(4)));
          }
          // 2. results of finished commands
          Object.keys(pending).forEach(function (k) {
            if (exists(pending[k])) {
              var t = fileText(pending[k]);
              remove(pending[k]);
              delete pending[k];
              statusAsked = 0;   // refresh the status right away
              if (t) { push('window.dpResult', t); }
            }
          });
          // 3. status every ~3 seconds
          var now = Date.now();
          if (statusRunning && exists(WORK + '/status.json')) {
            var st = fileText(WORK + '/status.json');
            remove(WORK + '/status.json');
            statusRunning = false;
            if (st) { push('window.dpStatus', st); }
          }
          if (!statusRunning && now - statusAsked > (TAB === 'home' ? 15000 : 1500)) { statusAsked = now; askStatus(); }
          // home tab: the monitor state (CPU, RAM, cores, cues) is refreshed every second, like the browser page
          if (stateRunning) {
            if (exists(WORK + '/state.json')) {
              var sj = fileText(WORK + '/state.json');
              var okj = false;
              try { JSON.parse(sj); okj = true; } catch (e) {}
              if (okj) { remove(WORK + '/state.json'); stateRunning = false; push('window.dpState', sj); }
            }
            if (now - stateAsked > 2500) { stateRunning = false; }
          }
          if (TAB === 'home' && !stateRunning && now - stateAsked > 1000) { askState(); }
        } catch (e) { /* keep the window alive */ }
      }
    }
};
var DP_EXT = {};
Object.keys(DP_METHODS).forEach(function (k) { DP_EXT[k] = DP_METHODS[k]; });
DP_EXT['applicationShouldTerminate:'] = { types: ['long', ['id']], implementation: function (app) { return askQuit(); } };
DP_EXT['windowShouldClose:'] = {
  types: ['bool', ['id']],
  implementation: function (w) {
    hideWin();      // the red button hides the window; quit with Cmd+Q (asks to confirm)
    return false;
  }
};
DP_EXT['powerOff:'] = { types: ['void', ['id']], implementation: function (n) { allowQuit(); } };
try {
  ObjC.registerSubclass({ name: 'DPDelegateQ', methods: DP_EXT });
  W.confirmQuit = true;
} catch (e) {
  log('quit confirmation not available: ' + e);
  ObjC.registerSubclass({ name: 'DPDelegate', methods: DP_METHODS });
}

var STEP = 'start';
function run(argv) {
  try { return runWindow(argv); }
  catch (e) { throw new Error('step ' + STEP + ': ' + e); }
}

function runWindow(argv) {
  var icon = argv[0], html = argv[2];
  W.html = html;
  LAUNCHER = argv[1];
  WORK = argv[3];
  // name shown next to the Apple menu and in the Dock: "The Endurance" instead of "osascript"
  try { $.NSProcessInfo.processInfo.processName = 'The Endurance'; } catch (e) {}
  if (argv[4] !== 'safe') {   // the launcher retries with 'safe' if this ever stops the window from opening
    try {
      var info = $.NSBundle.mainBundle.infoDictionary;
      info.setObjectForKey('The Endurance', 'CFBundleName');
      info.setObjectForKey('The Endurance', 'CFBundleDisplayName');
      log('app name set');
    } catch (e) { log('app name not set: ' + e); }
  }
  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyRegular);
  if (icon && exists(icon)) {
    var img = $.NSImage.alloc.initWithContentsOfFile(icon);
    if (img && !img.isNull) { app.setApplicationIconImage(img); }
  }
  W.delegate = W.confirmQuit ? $.DPDelegateQ.alloc.init : $.DPDelegate.alloc.init;
  app.setDelegate(W.delegate);
  try {   // Dock > Quit and AppleScript 'quit' ('aevt' = 0x61657674, 'quit' = 0x71756974)
    $.NSAppleEventManager.sharedAppleEventManager.setEventHandlerAndSelectorForEventClassAndEventID(W.delegate, 'dpQuitEvent:withReplyEvent:', 0x61657674, 0x71756974);
    log('quit event handler set');
  } catch (e) { log('quit event handler not set: ' + e); }
  // never reopen at login (macOS "Reopen windows when logging back in")
  try { inv(app, 'disableRelaunchOnLogin'); } catch (e) { log('relaunch flag not set: ' + e); }
  if (W.confirmQuit) {
    try {
      var wsn = inv($.NSWorkspace.sharedWorkspace, 'notificationCenter');
      wsn.addObserverSelectorNameObject(W.delegate, 'powerOff:', $.NSWorkspaceWillPowerOffNotification, null);
    } catch (e) { log('power-off observer not set: ' + e); }
  }

  STEP = 'menu'; log('step menu');
  // menu bar: The Endurance (quitting the app also stops the monitor) and Edit (copy / paste in the fields)
  var menubar = $.NSMenu.alloc.init;
  var appItem = $.NSMenuItem.alloc.init;
  menubar.addItem(appItem);
  var appMenu = $.NSMenu.alloc.initWithTitle('The Endurance');
  appMenu.addItem($.NSMenuItem.alloc.initWithTitleActionKeyEquivalent('Quit The Endurance (asks to confirm, stops the monitor)', 'terminate:', 'q'));
  appItem.title = 'The Endurance';
  appItem.submenu = appMenu;
  var editItem = $.NSMenuItem.alloc.init;
  menubar.addItem(editItem);
  var editMenu = $.NSMenu.alloc.initWithTitle('Edit');
  editMenu.addItem($.NSMenuItem.alloc.initWithTitleActionKeyEquivalent('Cut', 'cut:', 'x'));
  editMenu.addItem($.NSMenuItem.alloc.initWithTitleActionKeyEquivalent('Copy', 'copy:', 'c'));
  editMenu.addItem($.NSMenuItem.alloc.initWithTitleActionKeyEquivalent('Paste', 'paste:', 'v'));
  editMenu.addItem($.NSMenuItem.alloc.initWithTitleActionKeyEquivalent('Select All', 'selectAll:', 'a'));
  editItem.submenu = editMenu;
  app.mainMenu = menubar;

  STEP = 'window'; log('step window');
  var style = $.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable | $.NSWindowStyleMaskMiniaturizable | $.NSWindowStyleMaskResizable;
  W.win = $.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer(
    $.NSMakeRect(0, 0, 640, 840), style, $.NSBackingStoreBuffered, false);
  W.win.title = 'The Endurance';
  try { W.win.contentMinSize = $.NSMakeSize(560, 520); } catch (e) { log('minsize not set: ' + e); }
  W.win.backgroundColor = $.NSColor.blackColor;
  W.win.titlebarAppearsTransparent = true;
  W.win.releasedWhenClosed = false;
  if (W.confirmQuit) { try { W.win.delegate = W.delegate; } catch (e) { log('window delegate not set: ' + e); } }
  inv(W.win, 'center');

  STEP = 'web'; log('step web');
  W.web = $.WKWebView.alloc.initWithFrameConfiguration(
    W.win.contentView.bounds, $.WKWebViewConfiguration.alloc.init);
  W.web.autoresizingMask = 18;
  var src = fileText(html) || '<body style="background:#000;color:#ff8a00">window.html not found</body>';
  W.web.loadHTMLStringBaseURL(src, $.NSURL.fileURLWithPath(html));
  W.win.contentView.addSubview(W.web);

  STEP = 'timer'; log('step timer');
  W.sec = 0; setTimer(0.25);

  // never let macOS put this process to sleep (App Nap) or end it (automatic termination) while the monitor is running
  try { W.activity = $.NSProcessInfo.processInfo.beginActivityWithOptionsReason(0x00EFFFFF, 'The Endurance monitor'); } catch (e) { log('activity not set: ' + e); }
  try { $.NSProcessInfo.processInfo.disableAutomaticTermination('The Endurance monitor'); } catch (e) {}
  try { W.web.navigationDelegate = W.delegate; } catch (e) { log('navigation delegate not set: ' + e); }
  W.win.makeKeyAndOrderFront(null);
  app.activateIgnoringOtherApps(true);
  log('window ready, entering run loop');
  inv(app, 'run');
  log('run loop ended');
}
