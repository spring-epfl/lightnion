include config.mk

all: lighttor.min.js lighttor.bundle.js

lighttor.js:
	cat $(SOURCES) > $@

lighttor.min.js: lighttor.js
	$(COMPRESSOR) $< > $@

lighttor.bundle.js: lighttor.min.js $(BUNDLES)

sjcl.js:
	cp sjcl.patch sjcl
	cd sjcl && git apply sjcl.patch && make
	cd sjcl && cp sjcl.js ..
	cd sjcl && git reset --hard && rm sjcl.patch

cleanup-bundle:
	rm -f ./lighttor.bundle.js

lighttor-bundle:
	cat lighttor.min.js >> ./lighttor.bundle.js

lighttor-bundle-license:
	echo -e '\n\n--\n\nLICENSE lighttor\n\n--\n\n' >> $(BUNDLELICENSE)
	cat ../LICENSE.txt* >> $(BUNDLELICENSE)

sjcl-bundle: sjcl.js
	cat sjcl.js >> ./lighttor.bundle.js

sjcl-bundle-license:	
	echo -e '\n\n--\n\nLICENSE sjcl\n\n--\n\n' >> $(BUNDLELICENSE)
	cat sjcl/LICENSE.txt >> $(BUNDLELICENSE)

tweetnacl-bundle:
	cat tweetnacl-js/nacl.min.js >> ./lighttor.bundle.js
	cat tweetnacl-util-js/nacl-util.min.js >> ./lighttor.bundle.js

tweetnacl-bundle-license:
	echo -e '\n\n--\n\nLICENSE tweetnacl-js\n\n--\n\n' >> $(BUNDLELICENSE)
	cat tweetnacl-js/LICENSE >> $(BUNDLELICENSE)
	echo -e '\n\n--\n\nLICENSE tweetnacl-util-js\n\n--\n\n' >> $(BUNDLELICENSE)
	cat tweetnacl-util-js/LICENSE >> ./LICENSE.bundle.txt

clean:
	rm -f sjcl.js

mr_proper: clean
	rm -f $(BUNDLELICENSE)
	rm -f lighttor.js lighttor.min.js
	rm -f lighttor.bundle.js lighttor.bundle.min.js
