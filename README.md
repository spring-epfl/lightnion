Quick setup
-----------

Clone the repository and add it to your `PYTHONPATH`:
```sh
git clone --recurse-submodules https://github.com/plcp/tor-scripts/
cd lighttor
git checkout ltor
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD"
```

Some extra steps to run the proxy:
```sh
pip install -r requirements-proxy.txt
python -m lighttor.proxy
```

You'll find some examples under `./examples`.

Requirements
------------

We do recommend using `chutney`, you'll find some instructions
within `./tools/chutney`.

**Tested with `Python 3.6.5` against
`Tor version 0.3.3.6 (git-7dd0813e783ae16e)`.**

License
-------

This software is licensed under
[some license](LICENSE.txt_REPLACE_BEFORE_FIRST_RELEASE).
© 2018 Spring Lab (EPFL) and contributors.

Note that the aforementioned `some license` mention should have been replaced
before the distribution of the project. If you are able to read this, please
contact us to report the issue or to obtain a copy of the license.
