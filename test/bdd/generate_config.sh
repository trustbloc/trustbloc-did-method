#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

../../.build/bin/cli create-config --sidetree-url https://localhost:48326/sidetree/0.0.1 \
--tls-cacerts ./fixtures/keys/tls/ec-cacert.pem --sidetree-write-token rw_token \
--recoverykey-file fixtures/keys/recover/public.pem --updatekey-file fixtures/keys/update/public.pem \
--config-file $1 --output-directory ./fixtures/wellknown/jws
sleep 1

rm -rf ./fixtures/wellknown/jws/stakeholder.one/*
rm -rf ./fixtures/wellknown/jws/stakeholder.two/*

mkdir -p ./fixtures/wellknown/jws/stakeholder.one
mkdir -p ./fixtures/wellknown/jws/stakeholder.two

cp -r ./fixtures/wellknown/jws/stakeholder.one:8088/* ./fixtures/wellknown/jws/stakeholder.one
cp -r ./fixtures/wellknown/jws/stakeholder.two:8089/* ./fixtures/wellknown/jws/stakeholder.two

(cd fixtures/discovery-server ; docker-compose stop ; docker-compose up --force-recreate -d)
(cd fixtures/stakeholder-server ; docker-compose stop ; docker-compose up --force-recreate -d)

wait
sleep 5
