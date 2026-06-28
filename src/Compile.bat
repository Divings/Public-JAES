@echo off
cd /d ./

del *.class
del *.jar

javac --release 21 -encoding UTF-8 JAES.java
if errorlevel 1 goto :end

jar cfm JAES.jar MANIFEST.MF *.class
if errorlevel 1 goto :end

del *.class

:end
pause