#!/usr/bin/env bash

SCRIPT="$(realpath $0)"
SCRIPT_ROOT=`dirname "$SCRIPT"`
SSO_ROOT=`dirname "$SCRIPT_ROOT"`

source $SSO_ROOT/venv/bin/activate

python $SCRIPT_ROOT/yaml-to-html.py < $SCRIPT_ROOT/swagger.yaml > $SCRIPT_ROOT/swagger.html
