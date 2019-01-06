#!/usr/bin/env bash

. venv/bin/activate
pip install -U -r requirements.txt && rstcheck --report warning README.rst && cd docs && make html && cp -r _build/html/* ../../pywhoisxmlapi-docs/ && cd .. && flake8 pywhoisxmlapi.py scripts/whois.py && rm -rf dist/ build/ && python3 setup.py sdist && python3 setup.py bdist_wheel
