**inject**

The inject tool provides the injection functionality. 

**libbase**

The base library provides the hooking and unhooking functionality. The base library is compiled as a static library so it can be directly included in the actual instrumentation library. This is done so we can keep everything in /data/local/tmp. 

= build the inject tool =
```
cd InjectHook
cd inject
cd jni
ndk-build
cd ..
adb push libs/armeabi/inject /data/local/tmp/
cd ..

= build the instrumentation base code =

```
cd InjectHook
cd base
cd jni
ndk-build
cd ..
cd ..

= build fopen example =

```
cd fopen
cd jni
ndk-build
cd ..
adb push libs/armeabi/libfopen.so /data/local/tmp/


=== How to Run ===

```
adb shell
su
cd /data/local/tmp
>/data/local/tmp/Hook.log
usage:
./inject targetProcess  hookSoPath
cat Hook.log
