import Java from "frida-java-bridge";

rpc.exports = {
    init(stage, parameters) {
        var Color = {
            Reset: "\x1b[39;49;00m",
            Black: "\x1b[30;01m", Blue: "\x1b[34;01m", Cyan: "\x1b[36;01m", Gray: "\x1b[37;11m",
            Green: "\x1b[32;01m", Purple: "\x1b[35;01m", Red: "\x1b[31;01m", Yellow: "\x1b[33;01m",
            Light: {
                Black: "\x1b[30;11m", Blue: "\x1b[34;11m", Cyan: "\x1b[36;11m", Gray: "\x1b[37;01m",
                Green: "\x1b[32;11m", Purple: "\x1b[35;11m", Red: "\x1b[31;11m", Yellow: "\x1b[33;11m"
            }
        };
        // thanks: https://awakened1712.github.io/hacking/hacking-frida/
        function bytes2hex(array) {
            var result = '';
            for (var i = 0; i < array.length; ++i)
                result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
            return result;
        };

        Java.perform(function () {
            const Log = Java.use("android.util.Log");
            const TAG = "[blemon]";
            function log(msg) {
                Log.v(TAG, msg);
                console.log(TAG, msg);
            }
            log('[init]', stage, JSON.stringify(parameters));

            function setTimeoutJava(f, t) {
                const Runnable = Java.use('java.lang.Runnable');
                const Handler = Java.use("android.os.Handler");
                const JString = Java.use('java.lang.String');
                var task;
                var taskName = "RunnableTask" + JString.$new(""+f).hashCode();
                try {
                    task = Java.use(taskName);
                } catch(e) {
                    task = Java.registerClass({name: taskName, implements: [Runnable], methods: { run: f }});
                }
                Java.scheduleOnMainThread(function(){ Handler.$new().postDelayed(task.$new(), t); });
            };

            var retries = 60;

            function hookBLE() {
                var className = "";
                const lookup = Java.enumerateMethods('*!onCharacteristic*/u')
                if ((lookup.length == 1) && lookup[0].classes && (lookup[0].classes.length == 1)) {
                    className = lookup[0].classes[0].name;
                    log("[hook found]", className);

                    const cb = Java.use(className);
                    cb.onCharacteristicRead.implementation = function (g, c, s) {
                        const retVal = cb.onCharacteristicRead.call(this, g, c, s);
                        var uuid = c.getUuid();
                        log(
                            Color.Blue + "[BLE Read   <=]" + Color.Light.Yellow + " UUID: " + uuid.toString() + Color.Reset + " data: 0x" + bytes2hex(c.getValue())
                        );
                        return retVal;
                    };
                    cb.onCharacteristicWrite.implementation = function (g, c, s) {
                        const retVal = cb.onCharacteristicWrite.call(this, g, c, s);
                        var uuid = c.getUuid();
                        log(
                            Color.Green + "[BLE Write  =>]" + Color.Light.Yellow + " UUID: " + uuid.toString() + Color.Reset + " data: 0x" + bytes2hex(c.getValue())
                        );
                        return retVal;
                    };
                    cb.onCharacteristicChanged.implementation = function (g, c) {
                        const retVal = cb.onCharacteristicChanged.call(this, g, c);
                        var uuid = c.getUuid();
                        log(
                            Color.Cyan + "[BLE Notify <=]" + Color.Light.Yellow + " UUID: " + uuid.toString() + Color.Reset + " data: 0x" + bytes2hex(c.getValue())
                        );
                        return retVal;
                    };
                    log("[hooked]", className);
                } else {
                    if (retries--) {
                        log("Info: cannot find (unique) hooking class - retrying.");
                        setTimeoutJava(hookBLE, 1000);
                    } else {
                        log("Error: cannot find (unique) hooking class - aborting.");
                        log(JSON.stringify(lookup, null, 2));
                    }
                    return;
                }
                return;
            };

            hookBLE();
        });
    }
};
