#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did_method_rest
Feature: Using DID method REST API

  @e2e
  Scenario Outline: create trustbloc did and resolve it through
    Given TrustBloc DID is created through registrar "http://localhost:9080/1.0/register?driver-did-method-rest" with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve created DID through resolver URL "http://localhost:8080/1.0/identifiers" and validate key type "<keyType>", signature suite "<signatureSuite>"
    Examples:
      | keyType  |  signatureSuite             |
      | Ed25519  |  JwsVerificationKey2020     |
      | EC       |  JwsVerificationKey2020     |
      | Ed25519  |  Ed25519VerificationKey2018 |
