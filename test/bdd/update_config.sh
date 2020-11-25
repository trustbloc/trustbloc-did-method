#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

../../.build/bin/cli update-config \
--config-file $1 --output-directory ./fixtures/wellknown/jws \
--prev-consortium ./fixtures/wellknown/jws/did-trustbloc/testnet.trustbloc.local.json
