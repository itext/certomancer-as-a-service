#!/bin/sh

cd /app
uwsgi --socket "0.0.0.0:$PORT" --ini "/app/uwsgi.ini" --plugin python3