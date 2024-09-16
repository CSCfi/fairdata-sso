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

GUNICORN_ARGS="--workers 3 --timeout 60 --bind unix:/run/fairdata-sso.sock -u root -g nginx" 

DEBUG=`cat $SSO_CONFIG | grep "DEBUG" | grep "true"`

LOG_ROOT=`cat $SSO_CONFIG | grep "LOG_ROOT" | sed -e 's/\",.*$//' | sed -e 's/^.*\"//'`

if [ ! -d "$LOG_ROOT" ]; then
    LOG_ROOT="$SSO_ROOT"
fi

GUNICORN_ARGS="$GUNICORN_ARGS --error-logfile $LOG_ROOT/gunicorn_error.log"

if [ "$DEBUG" ]; then
    export FLASK_DEBUG=1
    GUNICORN_ARGS="$GUNICORN_ARGS --log-level=debug"
fi

cd $SSO_ROOT

source $SSO_ROOT/venv/bin/activate

gunicorn $GUNICORN_ARGS wsgi
