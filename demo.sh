#!/usr/bin/env sh

# (build the javascript files)
cd js-client
make mr_proper all
cd ..

# (run the proxy and serve the demo files)
source venv/bin/activate
PYTHONPATH="$PWD" python -m lighttor.proxy \
--purge-cache -vvvv --static ./js-client/demo/: ./js-client/demo/.dev/:.dev
