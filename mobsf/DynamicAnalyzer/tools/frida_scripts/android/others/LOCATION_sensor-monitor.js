Java.perform(function () {
    var SensorManager = Java.use('android.hardware.SensorManager');
    var timestamp = new Date().toISOString();
    SensorManager.getDefaultSensor.overload('int').implementation = function (sensorType) {
        send('--------------------');
        send("[Sensor Monitor] [" + timestamp + "] The following sensor is in use: ");
        send("[Sensor Monitor] [" + timestamp + "] getDefaultSensor called with sensor type: " + sensorType);
        var sensor = this.getDefaultSensor(sensorType);
        send("[Sensor Monitor] [" + timestamp + "] Retrieved sensor details:");
        send('\t- Type: ' + sensor.getType());
        send('\t- Name: ' + sensor.getName());
        send('\t- Vendor: ' + sensor.getVendor());
        send('\t- Version: ' + sensor.getVersion());
        send('\t- MaxRange: ' + sensor.getMaximumRange());
        send('\t- Resolution: ' + sensor.getResolution());
        send('\t- Power: ' + sensor.getPower());
        send('\t- MinDelay: ' + sensor.getMinDelay());
        return sensor;
    };

    // SensorManager.registerListener.overload('android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int').implementation = function (listener, sensor, rate) {
    //     send('[Sensor Monitor] registerListener called with sensor: ' + sensor);
    //     this.registerListener(listener, sensor, rate);
    // };
});
