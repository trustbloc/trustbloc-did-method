#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did_method_cli
Feature: Using DID method CLI

  @cli_createdid
  Scenario: create trustbloc did through CLI
    When TrustBloc DID is created through cli using domain "testnet.trustbloc.local"
    Then check cli created valid DID
