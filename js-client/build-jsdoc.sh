#!/bin/bash

cd src
rm -rf out
jsdoc header.js endpoint.js get.js ntor.js ../README.md
# $BROWSER ./out/index.html
exit 0

# jsdoc setup – checkout your community wiki before doing those
sudo pacman -S nodejs
sudo pacman -S npm

(cat <<__END__
# nodejs things
export PATH="$PATH:$HOME/.node_modules/bin"
export npm_config_prefix=~/.node_modules
__END__) >> /tmp/.zshrc

npm -g install jsdoc
