
# APK - Android Application Package

APK files contain all contents needed to run the application, including the following:

`AndroidManifest.xml`. This is an additional Android manifest file that describes the name, version, access rights, library and other contents of the APK file.

`assets/`. These are application assets and resource files included with the app.

`classes.dex`. These are compiled Java classes in the DEX file format that are run on the device.

`lib/.` This folder contains platform-dependent compiled code and native libraries for device-specific architectures, such as x86 or x86_64.

`META-INF/`. This folder contains the application certificate, manifest file, signature and a list of resources.

`res/`. This is a directory that holds resources -- for example, images that are not already compiled into resources.arsc.

`resources.arsc`. This is a file containing pre-compiled resources used by the app