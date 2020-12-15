#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

../../.build/bin/cli create-config --sidetree-url https://localhost:48326/sidetree/0.0.1 \
--tls-cacerts ../../test/bdd/fixtures/keys/tls/ec-cacert.pem --sidetree-write-token rw_token \
--recoverykey-file fixtures/keys/recover/public.pem --updatekey-file fixtures/keys/update/public.pem \
--config-file $1 --output-directory ./fixtures/wellknown/jws
sleep 1