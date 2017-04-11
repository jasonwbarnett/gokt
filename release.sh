#!/bin/bash


tag=$1
[[ -z $tag ]] && { echo "You must provide a tag, e.g. v0.1.0" 1>&2; exit 1; }

github-release release \
    --user jasonwbarnett \
    --repo gokt \
    --tag ${tag}

gox

for bin in gokt*; do
	github-release upload \
	    --user jasonwbarnett \
	    --repo gokt \
	    --tag ${tag}
	    --file $bin \
	    --name $bin
done
