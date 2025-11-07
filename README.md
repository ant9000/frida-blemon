# REVERSING THE BLE PROTOCOL OF A LED STRIP CONTROLLER

I recently bought a strip of individually addressable WS2812B LEDs. It came
with a controller that can be programmed with its IR remote, or via BLE. BLE
commands are sent using an Android app, namely
[Mister Star](https://play.google.com/store/apps/details?id=com.findn.mrstar).

I though it would be fun to know the BLE protocol, so the strip could be
controlled from a PC instead - or maybe integrated with a smart home appliance.

Well, it turned out to be an entertaining endeavour, and not overly difficult.
The script I used for sniffing BLE commands should be generic enough to be
useful for any Android phone - not necessarily for this specific application.

First, let's download APK tools and Frida stuff:

```
wget https://github.com/REAndroid/APKEditor/releases/download/V1.4.5/APKEditor-1.4.5.jar
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.12.1/apktool_2.12.1.jar
python3 -m venv venv
. venv/bin/activate
pip install frida-gadget frida-tools
```

Enable Developer options and USB debugging on your phone, then connect it to your PC.
Install Mister Star from Play Store on your phone.

Download it in a folder (it is a split APK):

```
mkdir mrstar
cd mrstar
for f in $(adb shell pm path com.findn.mrstar|cut -f2 -d:); do adb pull $f; done
cd ..
```

(the above command assumes you have Linux and a `bash`-compatible shell - adapt
it accordingly to your system).

Uninstall the app from phone, since the version we are going to produce in a
moment will have a different signature:

```
adb uninstall com.findn.mrstar
```

Merge the files into a single APK:

```
java -jar APKEditor-1.4.5.jar m -i mrstar/ -o mrstar_merged.apk
```

We can now inject frida-gadget into the APK (using a recent APKTool):

```
frida-gadget --apktool-path "java -jar apktool_2.12.1.jar" --sign mrstar_merged.apk
```

Now let's install our modified APK on phone:

```
adb install mrstar_merged/dist/mrstar_merged-aligned-debugSigned.apk
```

When we launch the app on phone, it will block waiting for Frida. Let's
connect a frida session with blemon.js script to debug BLE communication.

```
frida -l blemon.js -U -F -q -t 1000
```

Now we can interact with the app, assign permissions, etc. `blemon.js` will try
for 60 seconds to hook the unique class implementing the abstract class
`android.bluetooth.BluetoothGattCallback`; if it succeds, it will print all BLE
data exchanges.

For instance, here are the logs for turning the LEDs on and off respectively:

```
[BLE Write  =>] UUID: 0000fff3-0000-1000-8000-00805f9b34fb data: 0xbc01010155
[BLE Write  =>] UUID: 0000fff3-0000-1000-8000-00805f9b34fb data: 0xbc01010055
```

# LINKS

- APKEditor - we use it for merging split APK
  https://github.com/REAndroid/APKEditor
- APKTool - the goto tool for Android reversing
  https://apktool.org
- Frida - powerful debugging/reversing scripting framework
  https://frida.re/
- Frida Gadget - to simplify gadget injection
  https://github.com/ksg97031/frida-gadget
- blemon: the Frida script I used as the base for my own blemon.js
  https://github.com/optiv/blemon/
