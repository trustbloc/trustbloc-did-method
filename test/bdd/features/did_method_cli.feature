#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did_method_cli
Feature: Using DID method CLI

  @cli_did
  Scenario: test create and update did doc using cli
    Given Consortium config is generated with config file "./fixtures/wellknown/config.json"
    When TrustBloc DID is created through cli using domain "", direct url "https://localhost:48326/sidetree/v1"
    Then check cli created valid DID
    When TrustBloc DID is updated through cli using domain "testnet.trustbloc.local", direct url ""
    Then check cli updated DID
    When TrustBloc DID is recovered through cli using domain "", direct url "https://localhost:48326/sidetree/v1"
    Then check cli recovered DID
    When TrustBloc DID is deactivated through cli using domain "testnet.trustbloc.local", direct url ""
    Then check cli deactivated DID

