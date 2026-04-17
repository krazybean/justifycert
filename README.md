# justifycert

![PyPI](https://img.shields.io/pypi/v/justifycert)
![Python](https://img.shields.io/pypi/pyversions/justifycert)
![License](https://img.shields.io/github/license/krazybean/justifycert)
![CodeQL](https://github.com/krazybean/justifycert/actions/workflows/codeql.yml/badge.svg)

Fast, opinionated TLS certificate checks for developers.

## What it checks

- Expired or expiring certificates
- Weak signature algorithms such as SHA1
- Self-signed certificates
- Missing Subject Alternative Name (SAN)
- Basic chain validation for domain lookups

## Install

```bash
pip install justifycert
```

## Example

```bash
$ justifycert expired.badssl.com

✖ Certificate expired — renew immediately
```

## Use

```bash
justifycert example.com
justifycert --file cert.pem
justifycert example.com --json
```

## Library Usage

```python
from justifycert import analyze_cert

result = analyze_cert("google.com")
print(result["valid"])
```

## Development

Install build and publishing tools:

```bash
pip install build twine
```

Build the package:

```bash
python -m build
```

Upload to PyPI:

```bash
twine upload dist/*
```
