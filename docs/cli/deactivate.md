# Deactivate
This command used for Deactivating DID.

## Usage
```
deactivate-did [flags]
```

## Flags
* `domain` _[string]_ - URL to the TrustBloc consortium's domain.
* `sidetree-url` _[array|string]_ - Array of one or more Sidetree URLs.
* `sidetree-write-token` _[string]_ - The Sidetree write token.
* `tls-cacerts ` _[array|string]_ - Array of one or more CA cert paths.
* `tls-systemcertpool ` _[boolean]_ - Flag whether to use system certificate pool.
* `did-uri` _[string]_ - DID URI.
* `signingkey` _[string]_ - The private key PEM used for signing deactivate of the document.
* `signingkey-file` _[string]_ -  The file that contains the private key PEM used for signing deactivate of the document.
* `signingkey-password` _[string]_ -  The Signing key PEM password.

## Example

### deactivate cmd
```
deactivate-did --domain testnet.trustbloc.local --did-uri did:trustbloc:3XvwJ:EiDnJwbKHkHdaco4khFeBzvSL1hZ4eBGQq3q1Yjrpi5d4g  
--signingkey-file ./keys/recover2/key_encrypted.pem --signingkey-password 123
```
