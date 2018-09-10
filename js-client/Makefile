include config.mk

all: lightnion.min.js lightnion.bundle.js

lightnion.js: $(SOURCES)
	cat $(SOURCES) > $@

lightnion.min.js: lightnion.js
	$(COMPRESSOR) $< > $@

lightnion.bundle.js: lightnion.min.js $(BUNDLES)

sjcl.js:
	cp sjcl.patch sjcl
	cd sjcl && git apply sjcl.patch && make
	cd sjcl && cp sjcl.js ..
	cd sjcl && git reset --hard && rm sjcl.patch

cleanup-bundle:
	rm -f ./lightnion.bundle.js

lightnion-bundle:
	cat lightnion.min.js >> ./lightnion.bundle.js

lightnion-bundle-license:
	echo -e '\n\n--\n\nLICENSE lightnion\n\n--\n\n' >> $(BUNDLELICENSE)
	cat ../LICENSE.txt* >> $(BUNDLELICENSE)

sjcl-bundle: sjcl.js
	cat sjcl.js >> ./lightnion.bundle.js

sjcl-bundle-license:	
	echo -e '\n\n--\n\nLICENSE sjcl\n\n--\n\n' >> $(BUNDLELICENSE)
	cat sjcl/LICENSE.txt >> $(BUNDLELICENSE)

tweetnacl-bundle:
	cat tweetnacl-js/nacl-fast.min.js >> ./lightnion.bundle.js
	cat tweetnacl-util-js/nacl-util.min.js >> ./lightnion.bundle.js

tweetnacl-bundle-license:
	echo -e '\n\n--\n\nLICENSE tweetnacl-js\n\n--\n\n' >> $(BUNDLELICENSE)
	cat tweetnacl-js/LICENSE >> $(BUNDLELICENSE)
	echo -e '\n\n--\n\nLICENSE tweetnacl-util-js\n\n--\n\n' >> $(BUNDLELICENSE)
	cat tweetnacl-util-js/LICENSE >> ./LICENSE.bundle.txt

clean:
	rm -f sjcl.js

mr_proper: clean
	rm -f $(BUNDLELICENSE)
	rm -f lightnion.js lightnion.min.js
	rm -f lightnion.bundle.js lightnion.bundle.min.js
