Java.perform(function() {
    send('[Initialised] Screenshot Activity Monitor');
    var MediaProjection = Java.use('android.media.projection.MediaProjection');
    var VirtualDisplay = Java.use('android.hardware.display.VirtualDisplay');
    var timestamp = new Date().toISOString();
    VirtualDisplay.$init.overload('android.hardware.display.DisplayManagerGlobal', 'android.view.Display', 'android.hardware.display.IVirtualDisplayCallback', 'android.view.Surface').implementation = function (displayManagerGlobal, display, virtualDisplayCallback, surface) {
        // console.log('[*] VirtualDisplay constructor called');
        send("[Detect Screenshots] [" + timestamp + "] Screenshot taken by application. ");
        return this.$init(displayManagerGlobal, display, virtualDisplayCallback, surface);
    };
});