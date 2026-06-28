JAVAC = javac
JAR   = jar

JAVA_RELEASE = 25
ENCODING = UTF-8

SRC = JAES.java
CLASS = *.class
JARFILE = JAES.jar
MANIFEST = MANIFEST.MF

all: $(JARFILE)

$(CLASS): $(SRC)
	$(JAVAC) --release $(JAVA_RELEASE) -encoding $(ENCODING) $<

$(JARFILE): $(CLASS) $(MANIFEST)
	$(JAR) cfm $@ $(MANIFEST) $(CLASS)

rebuild: clean all

clean:
	rm -f *.class *.jar

PREFIX  = /opt/JAES
BINDIR  = $(PREFIX)/bin
WRAPPER = /usr/bin/jaes

install: all
	mkdir -p $(BINDIR)
	cp $(JARFILE) $(BINDIR)/
	echo '#!/bin/sh' > $(WRAPPER)
	echo 'exec java -jar $(BINDIR)/$(JARFILE) "$$@"' >> $(WRAPPER)
	chmod +x $(WRAPPER)