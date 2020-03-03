#!/bin/sh
# setup dependencies for integration tests

lightnion="../../../.."
lightnion-venv="venv/bin/activate"
chutney_dir="chutney"


# setup lightnion virtual environment
if [[ ! -e $lightnion_dir ]]; then
    virtualenv venv
    source venv/bin/activate
    pip install -r "${lightnion}/requirements.txt"
    pip install -r "${lightnion}/requirements-proxy.txt"
fi


# clone and setup chutney
if [[ ! -e $chutney_dir ]]; then
    git clone https://git.torproject.org/chutney.git
    # setup chutney from submodule in lightnion
    cp ${lightnion_dir}/tools/chutney/* "${chutney_dir}/"
    cd chutney
    git apply sandbox_patch
fi

