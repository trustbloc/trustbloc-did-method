#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did_method_rest
Feature: Using DID method REST API

  @e2e_universalresolver
  Scenario Outline: create trustbloc did and resolve through universalresolver
    Given TrustBloc DID is created through registrar "http://localhost:9080/1.0/register?driverId=driver-did-method-rest" with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve created DID through resolver URL "http://localhost:8080/1.0/identifiers" and validate key type "<keyType>", signature suite "<signatureSuite>"
    Examples:
      | keyType  |  signatureSuite             |
      | Ed25519  |  Ed25519VerificationKey2018 |


  @e2e_sidetree
  Scenario Outline: create trustbloc did and resolve through sidetree-mock
    Given TrustBloc DID is created through registrar "http://localhost:9080/1.0/register?driverId=driver-did-method-rest" with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve created DID through resolver URL "https://localhost:48326/sidetree/0.0.1/identifiers" and validate key type "<keyType>", signature suite "<signatureSuite>"
    Examples:
      | keyType  |  signatureSuite             |
      | Ed25519  |  JwsVerificationKey2020     |
      | P256     |  JwsVerificationKey2020     |
      | Ed25519  |  Ed25519VerificationKey2018 |
