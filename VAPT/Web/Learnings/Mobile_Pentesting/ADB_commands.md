# ADB (Android Debug Bridge)

`ADB (Android Debug Bridge)` is a command-line tool that enables communication between a computer and an Android device. ADB provides a variety of commands that allow developers and security testers to interact with an Android device, transfer files, install or remove applications, and collect information for debugging or security testing purposes.

Here are some common ADB commands:

`adb devices`: Lists all connected Android devices and their status.

`adb shell`: Opens a shell on the Android device, allowing the user to execute commands directly on the device.

`adb install [path to APK]`: Installs an Android application on the connected device.

`adb uninstall [package name]`: Uninstalls an application from the connected device.

`adb pull [remote file path] [local file path]`: Copies a file from the Android device to the local computer.

`adb push [local file path] [remote file path]`: Copies a file from the local computer to the Android device.

`adb bugreport`: Generates a detailed bug report of the Android device, including system logs, application data, and device information.

`adb screenrecord`: Records the Android device’s screen in real-time and saves it as a video file on the local computer.

`Start/ Stop ADB server`: If a device is connected start the adb server to be able to interact with the device.
`adb start-server`
`adb kill-server`

`adb logcat` : Displays the Android device’s system log in real-time.
adb logcatPrint the current device log to the console.

`adb logcat -d > [path_to_file]` Save the logcat output to a file on the local system.

`adb logcat -cThe parameter -c` will clear the current logs on the device. 

To capture logs of a specific app:
`adb shell pidof com.example.app` (gives you pid of specific app)

`adb logcat --pid 15236` displays log of that app's pid only) you can also append -f <filename> to adb logcat command

`adb logcat packagename`:[priority level: V, D, I, W, E, F, S]Filter log files by priority e.g. adb logcat com.myapp:E which prints all error logs

`adb shell` Allow you to interact with an Android device’s command-line interface directly from your computer

`adb shell pm list packages`: Lists all installed packages on the Android device.

`adb shell am start [intent]`: Starts an activity on the Android device using an intent.

`adb shell am force-stop com.android.settings`: Stops an activity on the Android device using an intent.

`adb shell input text [text]`: Simulates typing text on the Android device’s keyboard.

