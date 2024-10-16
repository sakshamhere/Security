

# Mobile Application Pentesting

It involves analyzing the `application’s source code`, `binary files`, and `network traffic` to find security flaws.

There are mainly 2 parts `Static and Dynamic analysis`

Static analysis involves examining an application’s code and configuration files without executing it.

Dynamic analysis involves testing the application in a running state to observe its behavior and interactions


# Set up the Environment

1. `Emulator`

Multiple android emulators are available like 

- Genymotion
- QEMU
- Memu
- NOX_Player etc.0

# How to install the application

Install from playstore — straightforward

# Extracting the APK from the device

Let’s now assume that the application is not available in the Google Play store. When an application is already installed on the device:

- The APK file of an installed application is stored in the directory 

`/data/app/<package name>-1/base.apk.`

- To get the package name, use the command `adb shell pm list packages | grep sampleapp` since the app name is often part of the package name

- Once you have the package name, use the command `adb shell pm path com.example.sampleapp` to get the full path of the APK file

- Finally, retrieve the base.apk file using `adb pull /data/app/com.example.sampleapp-1/base.apk`

# ADB and ADB commands

`ADB (Android Debug Bridge)` is a command-line tool that enables communication between a computer and an Android device. ADB provides a variety of commands that allow developers and security testers to interact with an Android device, transfer files, install or remove applications, and collect information for debugging or security testing purposes.


# Static Analysis

Static analysis involves analyzing an application’s code, resources, and configuration files without executing the application. 

This type of analysis is typically performed by analyzing the application’s source code or its compiled binary file (APK) using tools like 

- `APKtool`
- `dex2jar`

The goal of static analysis is to identify potential vulnerabilities in the code, `such as insecure coding practices, data leakage, or hard-coded credentials.`

# Android Package (APK)

The Android Package (APK) file is a compressed archive file that contains all the files needed to run an Android application on an Android device. The APK file is essentially a ZIP file that contains several components, including:

1. `AndroidManifest.xml`: This file contains information about the application, including its package name, version number, required permissions, and components such as activities, services, and broadcast receivers.

2. `Classes.dex:` This file contains the compiled Java bytecode for the application’s classes, which are executed by the Android Runtime (ART).

3. `Resources.arsc`: This file contains compiled resources such as strings, images, and layouts that are used by the application.

4. `lib/`: This folder contains compiled native code libraries for specific device architectures, such as ARM or x86.

5. `META-INF/`: This folder contains the manifest file, the certificate of the APK signature, and a list of all the files in the APK, along with their checksums.

6. `assets/`: This folder contains additional application data files, such as sound and video files, that are not compiled into the APK.

7. `res/`: This folder contains the application resources, such as layouts, strings, and images, in their original format before being compiled into the Resources.arsc file.

8. `Android System Files`: This folder contains system-level files such as the Android runtime, framework libraries, and system components that the application may use.


# Reverse Engineering

Mainly there are 2 Methods : `DEX → JAR → JAVA` and `APK → JAVA`

1. `DEX -> JAR -> JAVA`

`Dex2Jar`

The dex files are Dalvik executable files format, and are not human readable. So, we need to convert it back to some human eye friendly language.

`How to get the .dex file?`

Convert the `.apk` file into `.zip` file then Extract the zipped file and under extracted folder we find `classes.dex` file along with other files

`jd-gui`

Now in order to open the `classes.dex2jar` file we need a tool called `jdgui`. For that we just open the tool and add the classes.dex2jar file in it


2. `APK → JAVA`


We convert the APK file directly into the corresponding Java files. The biggest advantage of this method is, that on one hand it’s less complicated

To decompile the app from binary code directly into Java classes, we use the Android decompiler `JADX`. With `JADX`, we can simply open the APK file and view the source code.




# Testing Methodology 

# 1. Discovery
- Reconnasaince or Information Gathering

# 2. Analysis

- Static Analysis

- Dynamic Analysis

- IPC Analysis

- Reverse Engineering

# 3. Exploitation

# 4. Privilege Escalation

# 5. Reporting

************************************8

# Elements of Applications

Activiy -> BroadCast Receiver -> Content Provider -> Services

All these elements are conntected with `Intents`, Intents are nothing but a part of `IPC` Inter Process Communication

Intents
- Explicit
- Implicit

 