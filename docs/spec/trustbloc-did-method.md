# TrustBloc DID Method Specification 0.1

#### Spec Version
This is version `0.1` of the TrustBloc DID Method Specification.

## Introduction
_This section is non-normative_

The `did:trustbloc` DID method allows groups of independent entities to share custody of a DID registry consisting of [Sidetree](https://identity.foundation/sidetree/spec/) over a permissioned ledger.

Independent [*stakeholders*](#stakeholder) wishing to transact with one another using DIDs can come together to form a [*consortium*](#consortium) to manage their shared custody of a ledger.

This spec defines a [discovery service](#discovery-service). The discovery service provided by the TrustBloc DID Method allows a client to verify that a consortium is endorsed by its constituent stakeholders, verify that the configuration files of each stakeholder (which includes a list of Sidetree endpoints) are signed by the respective stakeholders, and use the provided Sidetree endpoints to perform Sidetree DID operations.

##### Terminology
###### Discovery Service:
A mechanism that allows clients to discover and validate DID operation endpoints.
###### Consortium:
A group of entities each of which manages DIDs with their own Sidetree nodes, all on the same ledger. A Consortium hosts the configuration files which a resolver uses when first connecting to the network.
###### Stakeholder:
An independent entity which follows some cooperative rules with the other stakeholders of a consortium to allow them all to manage DIDs using their own Sidetree nodes on the same ledger, and allow TrustBloc DID method clients to manage DIDs through any of the stakeholders. Each stakeholder hosts ledger nodes, hosts Sidetree endpoints, and signs policy changes.

#### `did:trustbloc` DID Format
A DID for the Block DID Method has the following ABNF format:

    trustbloc-did       = "did:trustbloc:" consortium-domain ":" document-id
    consortium-domain   = *idchar idchar
    document-id         = *idchar idchar
    idchar              = ALPHA / DIGIT / "-" / "." / "_"

Where `consortium-domain` is the URL hostname of the consortium (eg, `foo.example.net`) and `document-id` is the document ID as used in Sidetree.

## DID Method Operations
All method operations wrap a [Sidetree operation](https://github.com/decentralized-identity/sidetree/blob/master/docs/protocol.md#sidetree-rest-api), on a Sidetree endpoint found using the [discovery](#endpoint-discovery) process.

The operations are summarized here, and described in detail in the link above.

##### Create
A *Create* operation generates and returns a DID document, constructed using the data sent in the POST request.

##### Resolve
A *Resolve* operation fetches a document with a given DID. Note here - the Sidetree spec indicates that the request path looks like `[endpoint-path]/[did]`, with the examples all using the DID namespace `did:sidetree`. A Sidetree node configured for a TrustBloc consortium would instead use a DID namespace of `did:trustbloc:[consortium domain]`.

The consortium policy may indicate that multiple queries need to be made, to endpoints from multiple stakeholders, to validate a document. In this case, the client should verify that at least N (for an N given in the consortium policy) stakeholders agree on the value.

##### Update
An *Update* operation provides a patch to add or remove keys and service endpoints to a particular DID document.

##### Recover
A *Recover* operation replaces a DID document for a given DID with a new version of the document, in a way that ensures a stolen device cannot update the document using old operation passwords. This therefore recovers control of the DID document.

##### Deactivate
A *Deactivate* operation deletes the DID document for a given DID, leaving it as a historical artifact that cannot be accessed through the Sidetree endpoints.

## Endpoint Discovery
Most operations require the client to process configuration files to find Sidetree endpoints for DID operations. A TrustBloc DID contains the domain of the consortium, which is used to find a configuration file for the consortium. This lists the stakeholders of the consortium, along with their domains, where their configuration files can be found, each of which lists Sidetree endpoints belonging to that stakeholder. These are the endpoints used for DID Method operations, and these endpoints are also used to resolve stakeholder DIDs to verify signatures on configuration files. 

- Given a TrustBloc DID: `did:trustbloc:[domain]:[hash]`
- Check local cache for fresh config files from a previous bootstrapping.
- If there isn't any cached consortium config that matches the DID's domain, the response depends on the configuration of the client - it could abort, automatically bootstrap trust with the consortium, caching the config, or fetch and validate the consortium config but then ask the user for consent.
- If there is now a cached consortium config for the DID's domain, select a Sidetree endpoint from a cached stakeholder and perform the Sidetree operation.

### Discovery Servers
Every consortium and stakeholder must maintain at least one server which exposes the discovery configuration files described below. The respective files must be exposed under the web domain of the consortium or stakeholder.

##### Consortium Files
The policies of a consortium, along with information identifying the stakeholders, is stored under the consortium's domain, within `http://[consortium domain]/.well-known/did-trustbloc`

`.well-known/did-trustbloc` should have this file hierarchy:

    .well-known/did-trustbloc/
        [domain].json
        history/

`[domain].json`:
This file contains the current consortium configuration, according to this particular server.

`history`: contains the history database.

##### Consortium Config Files
A consortium config file is a JWS, signed by the stakeholders, with the payload being a JSON object containing:
  - `domain`: The domain name of the consortium
  - `policy`: [Consortium policy](#consortium-policy-configuration) configuration settings
  - `members`: A list of [consortium stakeholders](#stakeholder-list)
  - `previous`: The SHA256 hash of the previous version of this config file
  
Example of the format of the configuration data wrapped within the JWS:
```json
{
    "domain": "[consortium domain]",
    "policy": {
        "cache": {"max-age": 604800}
    },
    "members": [
        {
            "domain": "stakeholder.one",
            "did": "[stakeholder one's DID]",
            "public_key": {
                "id": "[stakeholder one's verification public key DID URL]",
                "jwk": {stakeholder one's verification public key in JWK format},
            }
        },
        {
            "domain": "stakeholder.two",
            "did": "[stakeholder two's DID]",
            "public_key": {
                "id": "[stakeholder two's verification public key DID URL]",
                "jwk": {stakeholder two's verification public key in JWK format},
            }
        }
    ],
    "previous": "[hash of previous consortium config file]"
}
```

The consortium config object JSON schema is [here](consortium.schema.json).

###### Consortium Endorsement Signatures
Stakeholders endorse a consortium configuration file using JWS multi-signature - they sign the JWS payload, with the consortium adding their signatures to the JWS.

###### Stakeholder List
The `"members"` element of a consortium config object is a JSON array, where each element describes a stakeholder within the consortium.

Each element of `"members"` is a JSON object containing the elements:
- `"domain"`: The web domain where its configuration can be found
- `"did"`: The `did:trustbloc` DID of the stakeholder, with the associated DID doc in Sidetree on the consortium ledger
- `"public_key"`: The verification key DID URL and public key in [IETF RFC 7517](https://tools.ietf.org/html/rfc7517) JWK format which can be used to verify this stakeholder's signature. The key should match the verification key in the stakeholder's DID doc.

##### History
The `history/` directory contains historical consortium configs. Each such file is named `[hash].json`, where `[hash]` is the SHA-256 hash of the given file.

##### Stakeholder Files
A stakeholder must expose the following files and directories within 

    .well-known/did-trustbloc/
        [domain].json
        history/
    .well-known/did-configuration

`[domain].json` is the stakeholder configuration file for this stakeholder.

`history/` is a directory of previous stakeholder configs for this stakeholder.

[`.well-known/did-configuration`](https://identity.foundation/specs/did-configuration/), a Well-Known DID Configuration resource, asserts a linkage between a group of DIDs and the domain which the configuration is exposed under. A stakeholder must have a Well-Known DID Configuration which asserts domain linkage:
 - Between the stakeholder's `did:trustbloc` DID (the same one contained within the consortium config) and its domain.

##### Stakeholder Configuration Files
Each of these files is named `[domain].json`, where `[domain]` is the URL domain, owned by the stakeholder, where you can find the canonical copy of the stakeholder's configuration.

A stakeholder's config file is a JWS, signed by the stakeholder, with the payload being a JSON object containing:
- The stakeholder's domain
- The stakeholder's DID (`did:trustbloc`)
- Stakeholder [policy settings](#stakeholder-policy)
- The stakeholder's Sidetree endpoints
- the SHA256 hash of the previous version of this config file

```json
{
    "domain": "stakeholder.one",
    "did": "[stakeholder one's DID]",
    "policy": {"cache": {"max-age": 604800}},
    "endpoints": [
        "http://endpoints.stakeholder.one/peer1/",
        "http://endpoints.stakeholder.one/peer2/"
    ],
    "previous": "[hash of previous stakeholder config file]"
}
```

The stakeholder config object JSON schema is [here](member.schema.json).

### Consortium Policy Configuration
The `policy` element of a consortium config object is a JSON object. Each key-value pair is a specific rule for the client to follow when processing consortium or stakeholder configuration files, or when resolving DIDs within the consortium.

##### Caching
`"cache": {"max-age": [number in seconds]}`

This 64 bit unsigned integer element specifies the length of time that a client should cache a copy of the consortium config.

##### Stakeholder Queries
`"num-queries": [number of queries]`

This 64 bit unsigned integer element specifies the number of stakeholders that a client should query when verifying a consortium configuration - whether for bootstrapping or for updating.

If this element is not present in the consortium policy, the default value of `num-queries` is the number of stakeholders within the consortium.

##### Sidetree Parameters
`"sidetree": {[parameters]}`

This object holds parameters which the client needs for Sidetree requests. The keys it must contain, with value types and example values, are as follows:

**Key** | **Value Type** | **Description** | **Example Value**
--- | --- | --- | ---
`"hash-algorithm"` | `string` | The hash algorithm used for Sidetree operation requests |  `"SHA256"`
`"key-algorithm"` | `string` | The key algorithm used for signing Sidetree operation requests | `ES256`
`"max-encoded-hash-length"` | `uint64` | The maximum string length of the hash created for the operation request | `100`
`"max-operation-size"` | `uint64` | The maximum size of the Sidetree operation request, in bytes | `8192`

The following keys are used for validating the backing datastructures used by Sidetree, and can be ignored by clients that don't intend to validate:

**Key** | **Value Type** | **Description** | **Example Value**
--- | --- | --- | ---
`"genesis-time"` | `uint` | The block in the blockchain's history where Sidetree is first activated | 0
`"max-operations-per-batch"` | `unit` | The maximum number of sidetree operations per batch | 10000

### Stakeholder Policy
The `policy` element of a stakeholder config object is a JSON object. Each key-value pair is a rule for the client to follow when processing this specific stakeholder config file, or for resolving DIDs using endpoints listed within this stakeholder config file.

##### Caching
`"cache": {"max-age": [number in seconds]}`

This 64 bit unsigned integer element specifies the length of time that a client should cache a copy of the stakeholder config.

### Bootstrapping Trust
The TrustBloc DID method is designed to offer several mechanisms for a client to confirm that it can trust the stakeholders to provide the DID doc ledger service.

In each mechanism, the client has the option to cache verified configuration files for a period of time (the cache lifetime being specified in the configuration), and in some of these, the client can automatically fetch and verify updates.

#### Automatic Bootstrapping
Automatic bootstrapping starts from a consortium domain - for example, the domain within a `did:trustbloc` DID. It processes the consortium config found at the consortium domain, processes stakeholder configs found at stakeholder domains, and then, with Sidetree endpoints listed within the stakeholder configs, it fetches the stakeholder DID docs which are used to verify stakeholder signatures on the consortium and stakeholder configs, thus verifying that the consortium provided is a valid consortium.

Automatic bootstrapping verifies that the consortium domain and stakeholder domains are endorsed by the DIDs of the stakeholders, but does not offer any proof of the identity or trust of the consortium or stakeholders. It can be used, for example, for resolving DIDs under the assumption that a DID owner would register a DID under a consortium that *they* trust.

The process is as follows:
- The client fetches the consortium configuration, and picks N of the listed stakeholders, where N is the value of the `num-queries` consortium policy configuration.
- For each of these stakeholders:
  - Fetch the stakeholder's TrustBloc configuration and did-configuration.
  - Use one of the Sidetree endpoints listed within to resolve the stakeholder's DID and retrieve its DID doc.
  - Verify that the `"public_key"` identified by its `"id"` DID URL value is expressed by the stakeholder's DID document.
  - Verify that the `"public_key"` JWK value matches the JWK of the key identified by the `"id"` DID URL.
  - Verify the signature on the stakeholder configuration, the stakeholder's signature on the consortium configuration and the signature on the did-configuration linkage assertions using this key.
  - If any of these steps fail, add another stakeholder to the list to replace this one.
- If less then N stakeholders have successfully verified (meaning the client has tried all stakeholders), this consortium's configuration is invalid.
- Otherwise:
  - Cache the valid configuration files

#### Skipping Bootstrapping
Skipping the bootstrapping: if you explicitly trust a particular stakeholder, you can go directly to their domain and trust the configuration within, using their endpoints for Sidetree operations. For example, you might be a member, employee or customer of a stakeholder organization.

#### Genesis File Bootstrapping
Like automatic bootstrapping, but the client is given a *genesis file*, a trusted consortium config file for a particular consortium, which the client can additionally verify by verifying stakeholder signatures.

If this genesis file is up-to-date with the state of the consortium, then it can be used as-is to fetch endpoints for performing DID operations. Otherwise, the genesis file serves as a trusted starting point for performing the history update process.

The genesis file is trusted due to manual review and approval - for example, provided by a vendor, or agreed-upon by the founding stakeholders of a consortium.

### Configuration Updates
When a client's cached configuration for a consortium is out of date from the consortium configuration stored on the consortium's server, the client may need to update. The TrustBloc DID method provides a mechanism for ensuring that updates to the configuration can be trusted, based on endorsements by trusted stakeholders within the consortium.

#### Automatically Updating the Configuration
This is a process to update automatically, to reach the current consortium configuration, while verifying that the updates being fetched are all valid.

- Get the current configuration from the consortium domain that is listed in the cached configuration you are updating.
- Construct a list of the history entries leading back from that config to the older, cached version:
  - Fetch the `previous` of the current configuration, and append it to your list.
  - Fetch the previous of this configuration, and continue fetching backwards in history until you've reached the direct descendant of the cached configuration.
- Iterate forwards from the cached configuration until you've reached the current server-side configuration:
  - With the current historical configuration under consideration as `check`, and the subsequent configuration as `next`:
  - Verify that sufficient stakeholders (per the [stakeholder queries](#stakeholder-queries) policy) in `check` have signed `next`. If this ever fails, then `check` is the last valid configuration. Depending on the use case, either abort, or use `check` as your configuration, cache it, and end the updating process.
- Cache the last valid configuration you reach in this loop, replacing the current cached configuration.

#### Manual Updating
In some use cases, you might choose never to automatically update to the latest consortium configuration. Instead, you can use manual review of a consortium configuration, and initialize using that config as a new genesis file.

### Adding and Removing Stakeholders
When adding a stakeholder to a consortium:
 - The stakeholder is added to the underlying ledger
 - The stakeholder deploys its own ledger peers and Sidetree peers
 - The stakeholder creates a `did:trustbloc` DID and DID doc on the ledger, using one of its Sidetree endpoints.
 - The stakeholder constructs the configuration that will go in `[stakeholder domain]/.well-known/did-trustbloc/`, and deploys the configuration to that domain.
 - The consortium pushes an update which adds the new stakeholder to the stakeholder list. This update is signed by M of the stakeholders that were already members of the consortium - it is not signed by the new stakeholder.
 
When removing a stakeholder from a consortium:
 - The consortium config pushes an update which removes the stakeholder from the consortium config list.
 - The stakeholder is removed from the ledger

### Implementation Notes
_This section is non-normative_

When implementing a client which performs DID operations in a consortium, it is useful to split out the *read* operation (Resolve) from the *edit* operations (Create, Update, Recover, Deactivate). A resolver does not need any special permissions, and resolution is the most common operation, being needed for any transaction using a DID as an identifier.

The edit operations require a client which can securely store key material - it must sign the contents of edit operation messages, and must generate and store one-time passwords for later provision, to prove ownership of the DID.

### Example Client Flows
_This section is non-normative_

This section contains worked examples demonstrating the full process a client takes, to discover endpoints in the consortium and perform a Sidetree operation.

###### Consortium files:
The consortium has a config JWS file at `consortium.net/.well-known/did-trustbloc/consortium.net.json` containing the payload:
```json
{
    "domain": "consortium.net",
    "policy": {
        "cache": {"max-age": 2419200},
        "num-queries": 2,
        "sidetree": {
            "hash-algorithm": "SHA256",
            "key-algorithm": "NotARealAlg2018",
            "max-encoded-hash-length": 100,
            "max-operation-size": 8192
        }
    },
    "members": [
        {
            "domain": "stakeholder.one",
            "did": "did:trustbloc:consortium.net:s1did12345",
            "public_key": {
                "id": "did:trustbloc:consortium.net:s1did12345#s1VERKEY123456789",
                "jwk": {"kty":"EC",...}
            }
        },
        {
            "domain": "stakeholder.two",
            "did": "did:trustbloc:consortium.net:s2did12345",
            "public_key": {
                "id": "did:trustbloc:consortium.net:s2did12345#s2VERKEY123456789",
                "jwk": {"kty":"EC",...}
            }
        },
        {
            "domain": "stakeholder.three",
            "did": "did:trustbloc:consortium.net:s3did12345",
            "public_key": {
                "id": "did:trustbloc:consortium.net:s3did12345#s3VERKEY123456789",
                "jwk": {"kty":"EC",...}
            }
        }
    ]
}
```
The JWS is signed by the keys listed within this file, namely, `s1VERKEY123456789`, `s2VERKEY123456789`, and `s3VERKEY123456789`

###### Stakeholder Files:
_Stakeholder one:_  
`stakeholder.one/.well-known/did-trustbloc/stakeholder.one.json` is a JWS signed by `s1VERKEY123456789` wrapping the following:
```json
{
    "domain": "stakeholder.one",
    "did": "did:trustbloc:consortium.net:s1did12345",
    "policy": {"cache": {"max-age": 604800}},
    "endpoints": [
        "http://endpoints.stakeholder.one/peer1/",
        "http://endpoints.stakeholder.one/peer2/"
    ]
}
```
`stakeholder.one/.well-known/did-configuration` is a DID configuration file containing a single domain linkage assertion, with the DID `did:trustbloc:consortium.net:s1did12345` and the JWT value (signed by `s1VERKEY123456789`) containing:
```json
{
  "iss": "did:trustbloc:consortium.net:s1did12345",
  "domain": "stakeholder.one"
}
```

_Stakeholder two:_  
`stakeholder.two/.well-known/did-trustbloc/stakeholder.two.json` is a JWS signed by `s2VERKEY123456789` wrapping the following:
```json
{
    "domain": "stakeholder.two",
    "did": "did:trustbloc:consortium.net:s2did12345",
    "policy": {"cache": {"max-age": 604800}},
    "endpoints": [
        "http://endpoints.stakeholder.two/peer1/",
        "http://endpoints.stakeholder.two/peer2/",
        "http://endpoints.stakeholder.two/peer3/"
    ]
}
```
`stakeholder.two/.well-known/did-configuration` is a DID configuration file containing a single domain linkage assertion, with the DID `did:trustbloc:consortium.net:s2did12345` and the JWT value (signed by `s2VERKEY123456789`) containing:
```json
{
  "iss": "did:trustbloc:consortium.net:s2did12345",
  "domain": "stakeholder.two"
}
```

_Stakeholder three:_  
`stakeholder.three/.well-known/did-trustbloc/stakeholder.three.json` is a JWS signed by `s3VERKEY123456789` wrapping the following:
```json
{
    "domain": "stakeholder.three",
    "did": "did:trustbloc:consortium.net:s3did12345",
    "policy": {"cache": {"max-age": 604800}},
    "endpoints": [
        "http://endpoints.stakeholder.three/peer1/"
    ]
}
```
`stakeholder.three/.well-known/did-configuration` is a DID configuration file containing a single domain linkage assertion, with the DID `did:trustbloc:consortium.net:s3did12345` and the JWT value (signed by `s3VERKEY123456789`) containing:
```json
{
  "iss": "did:trustbloc:consortium.net:s3did12345",
  "domain": "stakeholder.three"
}
```

_DID Docs_
Each stakeholder has a DID Doc which identifies their key (`s1VERKEY123456789`, `s2VERKEY123456789`, and `s3VERKEY123456789`) as belonging to their DID (`did:trustbloc:consortium.net:s1did12345`, `did:trustbloc:consortium.net:s2did12345`, and `did:trustbloc:consortium.net:s3did12345`, respectively).

###### Server Pre-steps:
- Generate and sign the config files
- Put the config files on the servers
- Put the DID docs for the stakeholders into Sidetree

##### Resolver resolves DID using genesis file
###### Client Pre-steps:
- Given the above consortium config as a [genesis file](#genesis-file-bootstrapping), cache the file.

###### Client Steps:
- Start with DID `did:trustbloc:consortium.net:IDCode123456789`
- Check consortium of DID
- Consortium matches a cached consortium config (the above)
- Check cached config's cache time
- Config does not need to be updated yet
- Fetch and process 2 of the stakeholder configs, since the consortium config indicates that 2 stakeholder queries need to be made.
- Verify these stakeholders' signatures
- Pick out several endpoints
- Use each stakeholder's endpoints to fetch the stakeholder's DID doc
- Verify stakeholder key in consortium config is a verification key in the did doc

At this point, discovery and verification are complete. The client can now execute its desired DID method operation, using one of the endpoints from one of the validated stakeholders.

##### Resolver resolves DID using Automatic Bootstrapping
###### Client Pre-steps:
- If the client needs to be configured to allow [automatic bootstrapping](#automatic-bootstrapping), enable this setting.

###### Client Steps:
- Start with DID `did:trustbloc:consortium.net:IDCode123456789`
- Check consortium of DID
- Consortium `consortium.net` missing from cache
- Fetch `consortium.net/.well-known/did-trustbloc/consortium.net.json`, validate format, and process as a consortium config file
- Perform the rest of the [Automatic Bootstrapping](#automatic-bootstrapping) algorithm. In summary:
  - Fetch and validate sufficiently many stakeholder configs, from the domains listed in the consortium config, to satisfy the `num-queries` policy in the consortium config.
  - Retrieve endpoints from these stakeholder configs, use these to retrieve the stakeholders' DID docs, verify stakeholder signatures.
  - Cache validated config files.
  - Present the list of endpoints parsed from said stakeholder configs, to be used for client DID method operations.

### Error Cases
Error cases which terminate the discovery process in a failure state:
- Consortium config unavailable: The consortium domain points to a server that isn't functional
- Insufficient endorsement: Insufficient stakeholders endorse the consortium

Error cases for a specific stakeholder, which can be ignored if sufficient other stakeholders are available:
- Stakeholder down: if a stakeholder's config servers are all down
- Stakeholder endpoints unavailable: if none of the stakeholder's Sidetree endpoints are functional
- No signature: The stakeholder has not signed a config it is expected to
- Invalid stakeholder signature: if a stakeholder signature fails to verify against the stakeholder's verification key(s)
- Inconsistent configuration: if the stakeholder mirrors consortium files, and these files are inconsistent across stakeholders.
