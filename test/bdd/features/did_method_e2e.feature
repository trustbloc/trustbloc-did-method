#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did_method_rest
Feature: Using DID method REST API

  @e2e
  Scenario: create bloc did and resolve it through
    Given Bloc DID is created from domain "localhost:80"
    Then Resolving created DID through resolver URL "http://localhost:8080/1.0/identifiers"
