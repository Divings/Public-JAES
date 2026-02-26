@echo off
cd /d ./
del *.class
del *.jar
javac --release 21 -encoding UTF-8 JAES.java 
jar cfm JAES.jar MANIFEST.MF *.class
pause