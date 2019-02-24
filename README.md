Quick setup
-----------

Clone the repository and add it to your `PYTHONPATH`:
```sh
git clone --recurse-submodules https://github.com/spring-epfl/lighttor lightnion
cd lightnion
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD"
```

Some extra steps to run the proxy:
```sh
pip install -r requirements-proxy.txt
python -m lightnion.proxy
```

You'll find some examples under `./examples`.

Requirements
------------

We do recommend using `chutney`, you'll find some instructions
within `./tools/chutney`.

**Tested with `Python 3.7.0` against
`Tor version 0.3.3.9 (git-45028085ea188baf)`.**

License
-------

This software is licensed under the
[BSD3 clause license](LICENSE).
© 2018-2019 Spring Lab (EPFL) and contributors.
