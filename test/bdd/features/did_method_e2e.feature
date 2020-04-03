#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did_method_rest
Feature: Using DID method REST API

  @e2e
  Scenario: create trustbloc did and resolve it through
    Given TrustBloc DID is created through registrar "http://localhost:9080/1.0/register?driver-did-method-rest"
    Then Resolving created DID through resolver URL "http://localhost:8080/1.0/identifiers"
