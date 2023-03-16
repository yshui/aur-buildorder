#!/bin/bash
SUBMODULES=($(git config --file .gitmodules --get-regexp path))

echo "source=("
# We need to convert from a relative folder path to a https://github.com path
(for ((i=0;i<${#SUBMODULES[@]};i+=2))
do
pathid=${SUBMODULES[$i]}
path=${SUBMODULES[$i+1]}

urlid=${pathid/%.path/.url}

url=$(git config --file .gitmodules $urlid |\
    awk -F/ '/^\.\./ {print "https://github.com/"$(NF-1)"/"$(NF-0)} /^http/ {print $0}')

urlbase=$(basename $url)
# remove trailing .git
urlbase=${urlbase%.git}
basepath=$(basename $path)
if [ "$urlbase" != "$basepath" ]; then
    echo "  $basepath::$url"
else
    echo "  $url"
fi
done) | sort 
echo ")"

(for ((i=0;i<${#SUBMODULES[@]};i+=2))
do
pathid=${SUBMODULES[$i]}
path=${SUBMODULES[$i+1]}
urlid=${pathid/%.path/.url}
basepath=$(basename $path)
echo "git config $urlid ../$basepath"
done) | sort
