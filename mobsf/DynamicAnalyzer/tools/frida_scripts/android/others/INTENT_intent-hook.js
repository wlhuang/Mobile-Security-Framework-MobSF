// * Source: https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/scripts/android-intent-monitor.js
send("[Initialised] Intent Intercept Monitoring");

function hook(intent) {
   var text = [];
   var tmp = null;
   tmp = intent.getComponent();
   if (tmp) {
       text.push("[Intent Intercept Monitoring] Activity: " + tmp.getClassName());
   }
   tmp = intent.getAction();
   if (tmp) {
       text.push("[Intent Intercept Monitoring] Action: " + tmp);
   }
   tmp = intent.getData();
   if (tmp) {
       text.push("[Intent Intercept Monitoring] URI: " + tmp);
   }
   tmp = intent.getType();
   if (tmp) {
       text.push("[Intent Intercept Monitoring] Type: " + tmp);
   }
   tmp = intent.getExtras();
   if (tmp) {
       var keys = tmp.keySet().iterator();
       while (keys.hasNext()) {
           var key = keys.next();
           var value = tmp.get(key);
           var type = "null";
           if (value) {
               try {
                   type = value.getClass().getSimpleName();
                   if (value.getClass().isArray()) {
                       value = Java.use('org.json.JSONArray').$new(value);
                   }
                   value = value.toString();
               } catch (error) {
                   value = null;
               }
           }
           text.push(value ? "Extras: " + key + " (" + type + "): " + value : "Extras: " + key + " (" + type + ")");
       }
   }
   text.push("--------------------");
   send(text.join("\n"));
}
function hookGetData() {
   hook(this);
   return this.getData();
}
function hookGetIntent() {
   var intent = this.getIntent();
   hook(intent);
   return intent;
}
setTimeout(function() {
   Java.perform(function() {
       send("");
       var Intent = Java.use("android.content.Intent");
       Intent.getData.implementation = hookGetData;
       var Activity = Java.use("android.app.Activity");
       Activity.getIntent.implementation = hookGetIntent;
   });
}, 0);