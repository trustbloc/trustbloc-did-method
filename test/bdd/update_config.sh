#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

../../.build/bin/cli update-config \
--config-file $1 --output-directory ./fixtures/wellknown/jws \
--prev-consortium ./fixtures/wellknown/jws/did-trustbloc/testnet.trustbloc.local.json

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
