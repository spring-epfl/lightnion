
all:
	cp sjcl.patch sjcl
	cd sjcl && git apply sjcl.patch && make
	cd sjcl && cp sjcl.js ..
	cd sjcl && git reset --hard && rm sjcl.patch
