#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Generates the well-known-server config files for the discovery service in BDD tests

pwd=`pwd`

rm -r test/bdd/fixtures/well-known-server/config
mkdir -p test/bdd/fixtures/well-known-server/config/

cd scripts/test-config-files/

for f in *; do
  # base64url encode payload: base64 -w 0 | sed 's/+/-/g; s/\//_/g'
  # then embed in a dummy jws and write to the config folder
  echo "{\"payload\":\"$(cat $f | base64 -w 0 | sed 's/+/-/g; s/\//_/g; s/=//g')\",\"signatures\":[{\"header\":{\"kid\":\"\"},\"signature\":\"\"}]}" > $pwd/test/bdd/fixtures/well-known-server/config/$f
done

cd "$pwd" || exit
