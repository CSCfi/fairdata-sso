#!/bin/bash

SCRIPT="$(realpath $0)"

SSO_ROOT=`dirname "$SCRIPT"`
export SSO_ROOT

if [ -z "$SSO_CONFIG" ]; then
    SSO_CONFIG="$SSO_ROOT/config.json"
    export SSO_CONFIG
fi

if [ -z "$SSO_SAML_CONFIG" ]; then
    export SSO_SAML_CONFIG="$SSO_ROOT/saml.json"
fi

source $SSO_ROOT/venv/bin/activate

cd $SSO_ROOT

DEBUG=`cat $SSO_CONFIG | grep "DEBUG" | grep "true"`

if [ "$DEBUG" ]; then
    export FLASK_ENV=development
fi

gunicorn --workers 3 --bind unix:/run/fairdata-sso.sock -u root -g nginx wsgi 

