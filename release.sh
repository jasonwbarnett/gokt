#!/bin/bash

github-release release \
    --user jasonwbarnett \
    --repo gokt \
    --tag v0.1.0

for bin in gokt*; do
	github-release upload \
	    --user jasonwbarnett \
	    --repo gokt \
	    --tag v0.1.0 \
	    --file $bin \
	    --name $bin
done
