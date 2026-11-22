#!/bin/zsh
set -e
cd -- "${0:A:h}"
python3 ipa_lab.py "$@"
