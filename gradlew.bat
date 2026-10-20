@echo off
setlocal
set "DIR=%~dp0"
set "JAVA_EXE=C:\Qt\jdk-21\jdk-21.0.12.1+1\bin\java.exe"
set "ANDROID_HOME=C:\Android"
set "ANDROID_SDK_ROOT=C:\Android"
"%JAVA_EXE%" -classpath "%DIR%gradle\wrapper\gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain %*
