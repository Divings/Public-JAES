@echo off
cd /d ./
del *.class
del *.jar
javac -encoding UTF-8 JAES.java
jar cfm JAES.jar MANIFEST.MF *.class  -C resources .
pause