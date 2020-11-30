# Recover
This command used for recovering DID.

## Usage
```
recover-did [flags]
```

## Flags
* `domain` _[string]_ - URL to the TrustBloc consortium's domain.
* `sidetree-url` _[array|string]_ - Array of one or more Sidetree URLs.
* `sidetree-write-token` _[string]_ - The Sidetree write token.
* `tls-cacerts ` _[array|string]_ - Array of one or more CA cert paths.
* `tls-systemcertpool ` _[boolean]_ - Flag whether to use system certificate pool.
* `did-uri` _[string]_ - DID URI.
* `publickey-file` _[string]_ - The file contains the DID public keys to be recovered.
* `service-file` _[string]_ - The file contains the DID services to be recovered.
* `nextupdatekey` _[string]_ - The public key PEM used for validating the signature of the next update of the document.
* `nextupdatekey-file` _[string]_ - The file that contains the public key PEM used for validating the signature of the next update of the document.
* `nextrecoverkey` _[string]_ - The public key PEM used for validating the signature of the next recovery of the document.
* `nextrecoverkey-file` _[string]_ - The file that contains the public key PEM used for validating the signature of the next recovery of the document.
* `signingkey` _[string]_ - The private key PEM used for signing the recovery of the document.
* `signingkey-file` _[string]_ -  The file that contains the private key PEM used for signing the recovery of the document.
* `signingkey-password` _[string]_ -  The Signing key PEM password.

## Example

### recover cmd
```
recover-did --domain testnet.trustbloc.local --did-uri did:trustbloc:3XvwJ:EiDZTmh3BNBzhwSlOdh3FwAdjzu4BkWly2MoTVNHoNdJpw 
--publickey-file ./publickeys.json  --service-file ./services.json 
--nextrecoverkey-file ./keys/recover2/public.pem --nextupdatekey-file ./keys/update3/public.pem 
--signingkey-file ./keys/recover/key_encrypted.pem --signingkey-password 123
```

### publickeys.json
```
[
 {
  "id": "key-recover-id",
  "type": "Ed25519VerificationKey2018",
  "purposes": ["authentication"],
  "jwkPath": "./fixtures/did-keys/recover/key1_jwk.json"
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

### services.json
```
[
  {
    "id": "svc-recover-id",
    "type": "type1",
    "priority": 1,
    "routingKeys": ["key1"],
    "recipientKeys": ["key1"],
    "serviceEndpoint": "http://www.example.com"
  }
]
```
