# TrustBloc DID Method Specification 0.1

#### Spec Version
This is version `0.1` of the Trustbloc DID Method Specification.

## `did:trustbloc` Method Specification
The `did:trustbloc` DID method allows groups of independent entities to share custody of a DID registry on a permissioned ledger.

Independent [*stakeholders*](#stakeholder) wishing to transact with one another using DIDs can come together to form a [*consortium*](#consortium) to manage their shared custody of a ledger.

This spec defines a [discovery service](#discovery-service). The discovery service provided by did:trustbloc allows a client to verify that a consortium is endorsed by its constituent stakeholders, verify that the configuration files of each stakeholder (which includes a list of sidetree endpoints) are signed by the respective stakeholders, and use the provided sidetree endpoints to perform sidetree DID operations.

##### Definitions
###### Discovery Service:
A mechanism that allows clients to discover and validate DID operation endpoints.
###### Consortium:
A group of Stakeholders which all manage DIDs with their own Sidetree nodes, all on the same ledger. A Consortium hosts the configuration files which a resolver uses when first connecting to the network.
###### Stakeholder:
An independent entity which follows some cooperative rules with the other stakeholders within the same consortium to allow them all to manage DIDs using their own Sidetree nodes on the same ledger, and allow trustbloc DID method clients to manage DIDs through any of the stakeholders. Stakeholders host ledger nodes, host sidetree endpoints, and sign policy changes.

#### `did:trustbloc` DID Format

A DID for the Block DID Method has the following format:

`did:trustbloc:[consortium domain]:[doc ID]`

Where `[consortium domain]` is the URL hostname of the consortium (eg, `foo.example.net`) and `[doc ID]` is the document ID as used in Sidetree.

#### Data Model

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
  - The domain name of the consortium
  - [Consortium policy](#consortium-policy-configuration) configuration settings
  - A list of stakeholders - containing, for each stakeholder:
    - The web domain where its configuration can be found
    - The did:trustbloc DID of the stakeholder, with the associated DID doc in Sidetree on the consortium ledger
    - The [`did:key`](https://w3c-ccg.github.io/did-method-key/) verification key which can be used to verify this stakeholder's signature. The key should match the verification key in the stakeholder's DID doc.
  - The SHA256 hash of the previous version of this config file
  
Example of the format of the configuration data wrapped within the JWS:
```json
{
    "domain": "[consortium domain]",
    "policy": {
        "cache": {"max-age": 604800}
    },
    "stakeholders": [
        {
            "domain": "stakeholder.one",
            "did": "[stakeholder one's DID]",
            "key": "[stakeholder one's verification key]"
        },
        {
            "domain": "stakeholder.two",
            "did": "[stakeholder two's DID]",
            "key": "[stakeholder two's verification key]"
        }
    ],
    "previous": "[hash of previous consortium config file]"
}
```

###### Consortium Endorsement Signatures
Stakeholders endorse a consortium configuration file using JWS multi-signature - they sign the JWS payload, with the consortium adding their signatures to the JWS.

##### Stakeholder Config Files
Each of these files is named `[domain].json`, where `[domain]` is the URL domain, owned by the stakeholder, where you can find the canonical copy of the stakeholder's configuration.

A stakeholder's config file is a JWS, signed by the stakeholder, with the payload being a JSON object containing:
- The stakeholder's domain
- The stakeholder's DID (did:trustbloc)
- Stakeholder [configuration settings](#stakeholder-configuration-settings)
- The stakeholder's Sidetree endpoints
- the SHA256 hash of the previous version of this config file

```json
{
    "domain": "stakeholder.one",
    "did": "[stakeholder one's DID]",
    "conf": {"cache": {"max-age": 604800}},
    "endpoints": [
        "http://endpoints.stakeholder.one/peer1/",
        "http://endpoints.stakeholder.one/peer2/"
    ],
    "previous": "[hash of previous stakeholder config file]"
}
```

##### History
The `history/` directory contains historical consortium configs. Each such file is named `[hash].json`, where `[hash]` is the SHA-256 hash of the given file.

##### Stakeholder Files
    .well-known/did-trustbloc/
        [domain].json
        history/

`[domain].json` is the stakeholder configuration file for this stakeholder.

`history/` is a directory of previous stakeholder configs for this stakeholder

### Consortium Policy Configuration
The `policy` element of a consortium config object is a JSON object. Each key-value pair is a specific rule for the client to follow when processing consortium or stakeholder configuration files, or when resolving DIDs within the consortium.

##### Caching
`"cache": {"max-age": [number in seconds]}`

This 64 bit unsigned integer element specifies the length of time that a client should cache a copy of the consortium config.

##### Stakeholder Queries
`"num-queries": [number of queries]`

This 64 bit unsigned integer element specifies the number of stakeholders that a client should query when verifying a consortium configuration - whether for bootstrapping or for updating.

If this element is not present in the consortium policy, the default value of `num-queries` is the number of stakeholders within the consortium.

### Stakeholder Configuration Settings

The `conf` element of a stakeholder config object is a JSON object. Each key-value pair is a rule for the client to follow when processing this specific stakeholder config file, or for resolving DIDs using endpoints listed within this stakeholder config file.

##### Caching
`"cache": {"max-age": [number in seconds]}`

This 64 bit unsigned integer element specifies the length of time that a client should cache a copy of the stakeholder config.

### Bootstrapping Trust
The Trustbloc DID method is designed to offer several mechanisms for a client to confirm that it can trust the stakeholders to provide the DID doc ledger service.

In each mechanism, the client has the option to cache verified configuration files for a period of time (the cache lifetime being specified in the configuration), and in some of these, the client can automatically fetch and verify updates.

#### Automatic Bootstrapping
Automatic bootstrapping starts from a consortium domain - for example, the domain within a `did:trustbloc` DID. It processes the consortium config found at the consortium domain, processes stakeholder configs found at stakeholder domains, and then, with sidetree endpoints listed within the stakeholder configs, it fetches the stakeholder DID docs which are used to verify stakeholder signatures on the consortium and stakeholder configs, thus verifying that the consortium provided is a valid consortium.

Automatic bootstrapping verifies that the consortium domain and stakeholder domains are endorsed by the DIDs of the stakeholders, but does not offer any proof of the identity or trust of the consortium or stakeholders. It can be used, for example, for resolving DIDs under the assumption that a DID owner would register a DID under a consortium that *they* trust.

The process is as follows:
- The client fetches the consortium configuration, and picks N of the listed stakeholders, where N is the value of the `num-queries` consortium policy configuration.
- For each of these stakeholders:
  - Fetch the stakeholder's configuration.
  - Use one of the sidetree endpoints listed within to resolve the stakeholder's DID and retrieve its DID doc.
  - Verify the signature on the stakeholder configuration and the signature on the consortium configuration using this DID doc.
  - If any of these steps fail, add another stakeholder to the list to replace this one.
- If less then N stakeholders have successfully verified (meaning the client has tried all stakeholders), this consortium's configuration is invalid.
- Otherwise:
  - Cache the valid configuration files

#### Skipping Bootstrapping
Skipping the bootstrapping: if you explicitly trust a particular stakeholder, you can go directly to their domain and trust the configuration within, using their endpoints for sidetree operations. For example, you might be a member, employee or customer of a stakeholder organization.

#### Genesis File Bootstrapping
Like automatic bootstrapping, but the client is given a *genesis file*, a trusted consortium config file for a particular consortium.

If this genesis file is up-to-date with the state of the consortium, then it can be used as-is to fetch endpoints for performing DID operations. Otherwise, the genesis file serves as a trusted starting point for performing the history update process.

The genesis file is trusted due to manual review and approval - for example, provided by a vendor, or agreed-upon by the founding stakeholders of a consortium.

### Configuration Updates

When a client's cached configuration for a consortium is out of date from the consortium configuration stored on the consortium's server, the client may need to update. The Trustbloc DID method provides a mechanism for ensuring that updates to the configuration can be trusted, based on endorsements by trusted stakeholders within the consortium.

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
 - The stakeholder deploys its own ledger peers and sidetree peers
 - The stakeholder creates a `did:trustbloc` DID and DID doc on the ledger, using one of its sidetree endpoints.
 - The stakeholder constructs the configuration that will go in `[stakeholder domain]/.well-known/did-trustbloc/`, and deploys the configuration to that domain.
 - The consortium pushes an update which adds the new stakeholder to the stakeholder list. This update is signed by M of the stakeholders that were already members of the consortium - it is not signed by the new stakeholder.
 
When removing a stakeholder from a consortium:
 - The consortium config pushes an update which removes the stakeholder from the consortium config list.
 - The stakeholder is removed from the ledger

### DID Method Operations

#### Finding a Sidetree Endpoint
Most operations require the client to process configuration files before finding Sidetree endpoints for DID operations. This always follows the same procedure:

- Given a trustbloc DID: `did:trustbloc:[domain]:[hash]`
- Check local cache for fresh config files from a previous bootstrapping.
- If there isn't any cached consortium config that matches the DID's domain, the response depends on the configuration of the client - it could abort, automatically bootstrap trust with the consortium, caching the config, or fetch and validate the consortium config but then ask the user for consent.
- If, after that, there is a cached consortium config for the DID's domain, select a sidetree endpoint from a cached stakeholder and perform the sidetree operation.

#### Method Operations

All method operations wrap a [Sidetree operation](https://github.com/decentralized-identity/sidetree/blob/master/docs/protocol.md#sidetree-rest-api), on a sidetree endpoint as determined by the process above.

The operations are summarized here, and described in detail in the link above.

##### Create

A *Create* operation generates and returns a DID document, constructed using the data sent in the POST request.

##### Resolve

A *Resolve* operation fetches a document with a given DID. Note here - the sidetree spec indicates that the request path looks like `[endpoint-path]/[did]`, with the examples all using the DID namespace `did:sidetree`. A sidetree node configured for a trustbloc consortium would instead use a DID namespace of `did:trustbloc:[consortium domain]`.

##### Update

An *Update* operation provides a patch to add or remove keys and service endpoints to a particular DID document.

##### Recover

A *Recover* operation replaces a DID document for a given DID with a new version of the document, in a way that ensures a stolen device cannot update the document using old operation passwords. This therefore recovers control of the DID document.

##### Revoke (Delete)

A *Revoke* operation deletes the DID document for a given DID, leaving it as a historical artifact that cannot be accessed through the sidetree endpoints.

### Implementation Notes

When implementing a client which performs DID operations in a consortium, it is useful to split out the *read* operation (Resolve) from the *edit* operations (Create, Update, Recover, Revoke). A resolver does not need any special permissions, and resolution is the most common operation, being needed for any transaction using a DID as an identifier.

The edit operations require a client which can securely store key material - it must sign the contents of edit operation messages, and must generate and store one-time passwords for later provision, to prove ownership of the DID.
