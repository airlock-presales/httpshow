#! /bin/bash

grep __VERSION__ app/__init__.py | sed -e 's,.*"\([0-9\.]*\).*".*,\1,'