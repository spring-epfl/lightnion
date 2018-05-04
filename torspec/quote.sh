#!/bin/bash
remote="https://git.torproject.org/torspec.git"

function die()
{
    echo "$@"
    exit 1
}

function +()
{
    echo -n "Execute '$@'? (^D to exit) "; read || die
    $@
}

if [ -d ./torspec ];
then
    [ -f ./torspec/.git/HEAD ] || (+ rm -rf ./torspec && git clone "$remote")
else
    git clone "$remote"
fi

grep -q "$remote" ./torspec/.git/config || die "Invalid remote: $PWD/torspec"

cd ./torspec
git pull --rebase > /dev/null || die "Unable to pull repository."

echo -n "File to quote: "; read fname
[ -f "./$fname" ] || die "Invalid file: $PWD/torspec/$fname"

git checkout HEAD -- "$fname" > /dev/null || die "Unable to checkout file."

rev="$(git rev-parse --short HEAD)"
target_name="$(basename "$fname"|sed "s/\(.\+\)\.\([^.]\+\)$/\1-$rev.\2/g")"

echo "$target_name"|grep -q "$rev" || die "Unable to quote file: $target_name"
cp "$fname" "../$target_name"
