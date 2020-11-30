# Update
This command used for updating DID.

## Usage
```
update-did [flags]
```

## Flags
* `domain` _[string]_ - URL to the TrustBloc consortium's domain.
* `sidetree-url` _[array|string]_ - Array of one or more Sidetree URLs.
* `sidetree-write-token` _[string]_ - The Sidetree write token.
* `tls-cacerts ` _[array|string]_ - Array of one or more CA cert paths.
* `tls-systemcertpool ` _[boolean]_ - Flag whether to use system certificate pool.
* `did-uri` _[string]_ - DID URI.
* `add-publickey-file` _[string]_ - The file contains the DID public keys to be added or updated.
* `remove-publickey-id` _[array|string]_ - Array of one or more public key IDs to be removed.
* `add-service-file` _[string]_ - The file contains the DID services to be added or updated.
* `remove-service-id` _[array|string]_ - Array of one or more service IDs to be removed.
* `nextupdatekey` _[string]_ - The public key PEM used for validating the signature of the next update of the document.
* `nextupdatekey-file` _[string]_ - The file that contains the public key PEM used for validating the signature of the next update of the document.
* `signingkey` _[string]_ - The private key PEM used for signing the update of the document.
* `signingkey-file` _[string]_ -  The file that contains the private key PEM used for signing the update of the document.
* `signingkey-password` _[string]_ -  The Signing key PEM password.

## Example

### update cmd
```
update-did --domain testnet.trustbloc.local --did-uri did:trustbloc:3XvwJ:EiDnJwbKHkHdaco4khFeBzvSL1hZ4eBGQq3q1Yjrpi5d4g  
--add-publickey-file ./publickeys.json --add-service-file ./services.json --signingkey-file ./keys/update/key_encrypted.pem --signingkey-password 123
--nextupdatekey-file ./keys/update2/public.pem --remove-publickey-id key1 --remove-service-id svc1 --remove-service-id svc2
```

### publickeys.json
```
[
 {
 "id": "key2",
 "type": "JwsVerificationKey2020",
 "purposes": ["capabilityInvocation"],
 "jwkPath": "./key2_jwk.json"
 },
 {
  "id": "key3",
  "type": "Ed25519VerificationKey2018",
  "purposes": ["authentication"],
  "jwkPath": "./key3_jwk.json"
 }
]
```

### key2_jwk.json
```
{
  "kty":"EC",
  "crv":"P-256",
  "x":"bGM9aNufpKNPxlkyacU1hGhQXm_aC8hIzSVeKDpwjBw",
  "y":"PfdmCOtIdVY2B6ucR4oQkt6evQddYhOyHoDYCaI2BJA"
}
```

### key3_jwk.json
```
{
  "kty":"OKP",
  "crv":"Ed25519",
  "x":"o1bG1U7G3CNbtALMafUiFOq8ODraTyVTmPtRDO1QUWg",
  "y":""
}
```

### services.json
```
[
  {
    "id": "svc3",
    "type": "type3",
    "priority": 3,
    "routingKeys": ["key3"],
    "recipientKeys": ["key3"],
    "serviceEndpoint": "http://www.example.com"
  }
]
```
