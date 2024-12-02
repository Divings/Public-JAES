@echo off
cd /d ./
del *.class
javac Encrypt.java
jar cfm Encrypt.jar MANIFEST.MF *.class  -C resources .
pause