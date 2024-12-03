@echo off
cd /d ./
del *.class
del *.jar
javac JAES.java
jar cfm JAES.jar MANIFEST.MF *.class  -C resources .
pause