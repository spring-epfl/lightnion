.PHONY: all install build test doc lint clean help submodules

# recursive wildcard
rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

CP = cp
CD = cd
NPM = npm
GIT = git
JSDOC = ./node_modules/jsdoc/jsdoc.js

VENDOR = ./vendor
SJCL = $(VENDOR)/sjcl
SJCL-GIT = $(SJCL)/.git
SJCL-BUILD = $(VENDOR)/sjcl.js

DIST = ./dist
LIGHTNION-BUNDLE = lightnion.bundle.js
LIGHTNION-BUNDLE-DIST = $(DIST)/lightnion.bundle.js
JSDOC-DIST = jsdoc/

SOURCES = $(call rwildcard,src/)

all: $(LIGHTNION-BUNDLE)

install:
	npm install

# build project
build: LIGHTNION-BUNDLE-DIST LIGHTNION-BUNDLE

# build javascript documentation
doc: jsdoc/index.html

# run unit tests
test:
	@./node_modules/mocha/bin/mocha -r jsdom-global/register --require esm --recursive --exclude "src/export.js" src/

# run javascript linter
lint:
	./node_modules/.bin/eslint src

# clean built files
clean:
	$(RM) $(LIGHTNION-BUNDLE)
	$(RM) $(DIST)/*
	$(RM) -r $(JSDOC-DIST)

# clean built files and dependencies
mr_proper: clean
	$(RM) $(SJCL-BUILD)

# show this help
help:
	@awk '/^#/{c=substr($$0,3);next}c&&/^[[:alpha:]][[:alnum:]_-]+:/{print substr($$1,1,index($$1,":")),c}1{c=0}' $(MAKEFILE_LIST) | column -s: -t

$(LIGHTNION-BUNDLE): $(LIGHTNION-BUNDLE-DIST)
	$(CP) $(LIGHTNION-BUNDLE-DIST) $@

$(LIGHTNION-BUNDLE-DIST): $(SJCL-BUILD) $(SOURCES)
	npm run build

$(SJCL-GIT):
	git submodule update --init --recursive

$(SJCL-BUILD): $(SJCL-GIT)
	cd $(SJCL) && ./configure --with-codecBytes --with-sha1
	cd $(SJCL) && make && cp sjcl.js ../
	# modify sjcl to export
	echo "export { sjcl };" >> $(SJCL-BUILD)

jsdoc/index.html: $(SOURCES)
	$(JSDOC) -r -d $(JSDOC-DIST) src/