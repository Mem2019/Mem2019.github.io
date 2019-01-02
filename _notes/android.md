# introduction

seperate android framework and linux kernel

UID of APPs

`u0_aXX`

`manifest.xml` to acquire previledge when install

SELinux, domain of root is not correct

Recovery is a small system, it can access all devices, 解锁, clear all user data

# tool chain

Android studio

JEB, including debug

jadx, open source decompiler

Smali, BakSmali, APKTool

IDA: debug native

compile android source code, e.g. using server

## reversing

res directory: processed resouces

asserts directory: unprocessed resources

Inner Class: `XXX$XXX`

## native

### JNI register

static/dynamic(RegisterNativeMethods)

### JNI_OnLoad

### JNIEnv

## packing

### DexClassLoader/PathClassLoader

## adb

adbd: a process

implement by port forwarding

## debug

`android:debuggable="true" //in manifest.xml`

`ro.debuggable=1 //in OS`

...

smali idea + IDA pro

`adb shell am start -D -n com.j.XXXX.XXXX`

method tracing

## unpacking

### brute force search dex header

### function bp

`dvmDexFileOpenPartial`: optimize dex to odex, addr, len

`DexFile::DexFile && OpenAndReadMagic(ART)` 

### DexHunter AppSpear

## obsfucation

obsfucation instruction

name obsfucation: 山海经, rename according to name information using JEB script

## Hook

Hook Everything: Xposed Frida

Hook Self: VirtualXposed Legend

## 4 Components

Activity, Service, Content Provider, Broadcast Reciever

## Application Security

memory corruption, logic vulnerability, web security(H5 app)

`addJavascriptInterface`, js call java function, can attack Java reflection

save secret data in SD card

## root

`adb root` to let adb root

### superSU

## debug environment configuration

1. `java -jar apktool_2.3.3.jar if XXX.apk -p . -f`
2. `java -jar apktool_2.3.3.jar d XXX.apk -p . -f`
3. copy the directory `XXX` for Android Studio to use
4. `Import Project`, select directory `XXX`
5. Right click `XXX` folder in `project` tab, `Mark Directory As` and `Source Root`
6. `Tools > Android > Android Device Monitor`
7. start the emulator
8. `Run > Edit Configuration > Remote`, set debug port as the one shown in DDMS (or 8700)
9. start the debug