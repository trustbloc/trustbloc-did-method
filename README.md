[![Release](https://img.shields.io/github/release/trustbloc/trustbloc-did-method.svg?style=flat-square)](https://github.com/trustbloc/trustbloc-did-method/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/trustbloc-did-method/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/trustbloc-did-method)

[![Build Status](https://dev.azure.com/trustbloc/edge/_apis/build/status/trustbloc.trustbloc-did-method?branchName=main)](https://dev.azure.com/trustbloc/edge/_build/latest?definitionId=38&branchName=main)
[![codecov](https://codecov.io/gh/trustbloc/trustbloc-did-method/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/trustbloc-did-method)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/trustbloc-did-method)](https://goreportcard.com/report/github.com/trustbloc/trustbloc-did-method)

# TrustBloc DID Method

This repo defines the trustbloc DID method, which is described [in the spec](/docs/spec/trustbloc-did-method.md).

The TrustBloc DID Method REST server docker image serves requests from the HTTP drivers of the [DIF universal resolver](https://github.com/decentralized-identity/universal-resolver) and [universal registrar](https://github.com/decentralized-identity/universal-registrar/).

## Build
To build from source see [here](/docs/build.md).

## CLI
Manage DID's.
- [Create DID](/docs/cli/create.md)
- [Update DID](/docs/cli/update.md)
- [Recover DID](/docs/cli/recover.md)
- [Deactivate DID](/docs/cli/deactivate.md)


## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
