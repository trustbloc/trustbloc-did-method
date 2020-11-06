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
    When TrustBloc DID is created through cli using domain "testnet.trustbloc.local", direct url ""
    Then check cli created valid DID
    When TrustBloc DID is updated through cli using domain "", direct url "https://localhost:48326/sidetree/0.0.1"
    Then check cli updated DID
