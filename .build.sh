#!/bin/bash
cd "${0%/*}"
OUTPUT="${1:-TA_extrahop.spl}"
chmod -R u=rwX,go= *
chmod -R u-x+X *
chmod -R u=rwx,go= *
python3.9 -m pip install --upgrade -t lib -r lib/requirements.txt --no-dependencies
cd ..
tar -cpzf $OUTPUT --exclude=.* --overwrite TA_extrahop 