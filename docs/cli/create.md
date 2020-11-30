# Create
This command used for creating DID.

## Usage
```
create-did [flags]
```

## Flags
* `domain` _[string]_ - URL to the TrustBloc consortium's domain.
* `sidetree-url` _[array|string]_ - Array of one or more Sidetree URLs.
* `sidetree-write-token` _[string]_ - The Sidetree write token.
* `tls-cacerts ` _[array|string]_ - Array of one or more CA cert paths.
* `tls-systemcertpool ` _[boolean]_ - Flag whether to use system certificate pool.
* `publickey-file` _[string]_ - The file contains the DID public keys.
* `service-file` _[string]_ - The file contains the DID services.
* `recoverykey` _[string]_ - The public key PEM used for recovery of the document.
* `recoverykey-file` _[string]_ - The file that contains the public key PEM used for recovery of the document.
* `updatekey` _[string]_ - The public key PEM used for validating the signature of the next update of the document.
* `updatekey-file` _[string]_ - The file that contains the public key PEM used for validating the signature of the next update of the document.

## Example

### create cmd
```
create-did --domain testnet.trustbloc.local --publickey-file ./publickeys.json --service-file ./services.json 
--recoverykey-file ./keys/recover/public.pem --updatekey-file ./keys/update/public.pem
```

### publickeys.json
```
[
 {
  "id": "key1",
  "type": "Ed25519VerificationKey2018",
  "purposes": ["authentication"],
  "jwkPath": "./key1_jwk.json"
 },
 {
  "id": "key2",
  "type": "JwsVerificationKey2020",
  "purposes": ["capabilityInvocation"],
  "jwkPath": "./key2_jwk.json"
 }
]
```

### key1_jwk.json
```
{
  "kty":"OKP",
  "crv":"Ed25519",
  "x":"o1bG1U7G3CNbtALMafUiFOq8ODraTyVTmPtRDO1QUWg",
  "y":""
}
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

### services.json
```
[
  {
    "id": "svc1",
    "type": "type1",
    "priority": 1,
    "routingKeys": ["key1"],
    "recipientKeys": ["key1"],
    "serviceEndpoint": "http://www.example.com"
  },
  {
    "id": "svc2",
    "type": "type2",
    "priority": 2,
    "routingKeys": ["key2"],
    "recipientKeys": ["key2"],
    "serviceEndpoint": "http://www.example.com"
  }
]
```
