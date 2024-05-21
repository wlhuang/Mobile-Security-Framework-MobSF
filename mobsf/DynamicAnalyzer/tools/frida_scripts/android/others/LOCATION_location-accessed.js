send('[Initialised] Location Monitor');
setInterval(function () {
    try {
        var locationManager = Java.use("android.location.LocationManager");
        var context = Java.use("android.content.Context");
        var provider = "gps";
        var timestamp = new Date().toISOString();
        locationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener', 'android.os.Looper').implementation = function (provider, minTime, minDistance, listener, looper) {
            send('--------------------');
            send("[Detect Location] [" + timestamp + "] Location access activities detected");
            send("[Detect Location] [" + timestamp + "] Location requested for provider: ");
            send(provider);
            return this.requestLocationUpdates(provider, minTime, minDistance, listener, looper);
        };

        locationManager.isProviderEnabled.overload('java.lang.String').implementation = function (provider) {
            var isEnabled = this.isProviderEnabled(provider);
            if (isEnabled) {
                send('--------------------');
                send("[Detect Location] [" + timestamp + "] Location access activities detected");
                send("[Detect Location] [" + timestamp + "] Location provider is detected:");
                send(provider);
            } else {
                send('--------------------');
                send("[Detect Location] [" + timestamp + "] Location access activities not detected");
                send("[Detect Location] [" + timestamp + "] Location provider is not detected: ");
                send(provider);
            }
            return isEnabled;
        };
    } catch (e) {
        console.error(e);
    }
}, 1000);