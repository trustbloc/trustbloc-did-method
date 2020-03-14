# TrustBloc DID Method Specification

## `did:trustbloc` Method Specification

### 

The `did:trustbloc` DID method allows groups of independent organizations to share custody of a DID registry on a permissioned ledger.

Independent *stakeholder* organizations which wish to transact with one another using DIDs can come together to form a *consortium* to manage their shared custody of a ledger.

The DID method operates as a discovery service that allows resolvers to discover the stakeholder organizations within a consortium, verify that the consortium itself is endorsed by the stakeholders, and access sidetree endpoints owned and exposed by the individual stakeholders, which the resolver can subsequently use to perform DID document operations within the consortium.

Definitions:

- Consortium: a group of Stakeholder organizations which all manage DIDs with their own Sidetree nodes, all on the same ledger. A Consortium hosts the configuration files which a resolver uses when first connecting to the network.
- Stakeholder organization (or just stakeholder): an independent organization which follows some cooperative rules with the other stakeholder organizations within the same consortium to allow them all to manage DIDs using their own Sidetree nodes on the same ledger, and allow resolvers to manage DIDs through any of the stakeholders. Stakeholders host ledger nodes, host sidetree endpoints, and sign policy changes.

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
  - Consortium policy configuration settings
  - A list of stakeholders - containing, for each stakeholder:
    - The web domain where its configuration can be found
    - The did:trustbloc DID of the stakeholder, with the associated DID doc in Sidetree on the consortium ledger
  - The hash of the previous version of this config file

###### Consortium Endorsement Signatures
Stakeholders endorse a consortium configuration file using JWS multi-signature - they sign the JWS payload, with the consortium adding their signatures to the JWS.

##### Stakeholder Config Files
Each of these files is named `[domain].json`, where `[domain]` is the URL domain, owned by the stakeholder organization, where you can find the canonical copy of the stakeholder's configuration.

A stakeholder's config file is a JWS, signed by the stakeholder, with the payload being a JSON object containing:
- The stakeholder's domain
- The stakeholder's DID (did:trustbloc)
  - TODO: also include a did:web DID doc? Same DID, same verkeys, used for bootstrapping.
- Stakeholder custom configuration settings
- The stakeholder's Sidetree endpoints
- the hash of the previous version of this config file

TODO: this should probably be in a secondary file, or stored in a way that's easy to detach without risk of screwing up the payload text
- A detached JWS signature on the file, created by the stakeholder

##### History
The `history/` directory contains historical consortium configs. Each such file is named `[hash].json`, where `[hash]` is the SHA-256 hash of the given file.

TODO: instead of separate history files, have a complete history database file, as either an object or a concat JSON?

TODO: consortium history may need to cache the stakeholder configs and verkeys - since these can be replaced on the stakeholder domain (or the stakeholder could disappear completely), with the associated consortium configs being subsequently unverifiable.


##### Stakeholder Files
    .well-known/did-trustbloc/
        [domain].json
        history/

`[domain].json` is the stakeholder configuration file for this stakeholder.

`history/` is a directory of previous stakeholder configs for this stakeholder

TODO: is a history for the stakeholder config necessary? If the consortium caches historical stakeholder info - specifically, DID -> verkey mappings so historical consortium files can be verified, then the stakeholders don't need to keep historical data, or even exist any longer.

<!--
TODO:
- Resolver has to check for consortium changes - how often?
  - update check frequency or cache lifetime should be part of the policy, or specified in the particular configuration file
- when the resolver hits stakeholders to verify the consortium policy config, if it finds that a stakeholder has a newer version of a file than the consortium, how does it respond?
 - update to the latest version that has sufficient endorsement?
 
- Policy may specify that a number of independent queries have to be made (queries made to endpoints 
  from different organizations in the consortium). TODO is to justify why.
  - This isn't about independent queries for regular use, but independent queries when bootstrapping trust, to verify that stakeholders named in the consortium config have signed the consortium config (and signed their own stakeholder config) with keys that are associated with did docs on the ledger
  - maybe we can suggest resolving stakeholder X's did doc using stakeholder Y's endpoint, to verify the stakeholders are on the same ledger?
    - but then, if they all sign the same consortium config, which points to all of them, we don't need this complication
--> 
### Bootstrapping Trust

The Bloc DID method is designed to offer several mechanisms for a resolver to confirm that it can trust the stakeholders to provide the DID doc ledger service. 

In each mechanism, the resolver has the option to cache verified configuration files for a period of time (the cache lifetime being specified in the configuration), and in some of these, the resolver can automatically fetch and verify updates.

#### Automatic Bootstrapping
Automatic bootstrapping relies on the assumption of trust in the owner of a web domain. In resolving a did:trustbloc DID, the resolver assumes the consortium domain in the DID is safe, and that the stakeholder domains within the consortium config are also safe and correct.

On a first connection by a resolver to the did:trustbloc method, the did method provides a mechanism for the resolver to establish trust in the consortium and stakeholders.

A resolver can begin by assuming trust in the consortium domain contained within a bloc DID. The config found there will inform the resolver about all the stakeholder organizations within the consortium. The resolver can trust the authenticity of these stakeholders based on their domain name registration, as well as their inclusion within the consortium config. 

The resolver must verify at least M stakeholders, to retrieve their endpoints and confirm their signatures on the consortium config.

For each stakeholder, the resolver fetches the stakeholder config from their domain. This includes a list of Sidetree endpoints managed by the stakeholder. With one of these, the resolver can resolve the stakeholder's DID to retrieve the stakeholder's DID doc. This DID Doc contains the key used to verify the signature on the stakeholder's config file, and one of the signatures on the consortium config file.

Once the resolver has verified M signatures on the consortium, via this process, it can cache the configuration info, having established trust. The request to resolve a DID can then proceed, and further requests can proceed directly to a cached endpoint.

#### Skipping Bootstrapping
Skipping the bootstrapping: if you explicitly trust a particular stakeholder, you can go directly to their domain and trust the configuration within, using their endpoints for sidetree operations. For example, you might be *part* of the stakeholder organization.

#### Genesis File Bootstrapping
Like automatic bootstrapping, but the resolver is given a number of "genesis files", each of which is a consortium config file for a particular consortium. The resolver then goes to these consortia and their stakeholders to verify the consortia configs, and goes through the update process for each genesis file, to cache the latest consortium config for each. This mechanism allows the resolver to initialize with a trusted configuration (provided by a vendor, verified manually, through contractual agreement, etc) and ensure it uses trusted endpoints and configuration from that point on.

### Configuration Updates

When a resolver's cached configuration for a consortium is out of date from the consortium configuration stored on the consortium's server, the resolver may need to update.

#### Automatically Updating the Configuration

<!-- TODO: section heading name - this isn't necessarily automatic in trigger, but rather automated in procedure. -->

This is a process to update to automatically, to reach the current consortium configuration, while verifying that the updates being fetched were all valid.

- Get the history and current configuration from the consortium domain that is listed in the cached configuration you are updating.
- Find the entry in the history database for your cached configuration:
  - Hash the cached configuration, and find the entry with that key.
- Iterate until you've reached the current configuration:
  - With the current historical configuration under consideration as `check`, and the subsequent configuration as `next`
  - Verify that sufficient stakeholders in `check` have signed `next`. If this ever fails, then `check` is the last valid configuration. Depending on the use case, either abort, or use `check` as your configuration, cache it, and end the updating process.
  - Iterate forward until there is no `next`.

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
 - Permission to change the stakeholder's did:trustbloc DID doc is revoked, meaning the DID doc will stay unchanged, allowing consortium history to be verified against this DID doc.

TODO: Removals should probably require greater consent among the stakeholders than other operations.

### DID Method Operations

#### Finding a Sidetree Endpoint
Most operations require the resolver to process configuration files before finding Sidetree endpoints for DID operations. This always follows the same procedure:

- Given a bloc DID: `did:trustbloc:[domain]:[hash]`
- Check local cache for fresh config files from a previous bootstrapping.
- If there isn't any cached consortium config that matches the DID's domain, the response depends on the configuration of the resolver - it could abort, or automatically bootstrap trust with the consortium, caching the config.
- If, after that, there is a cached consortium config for the DID's domain, select a sidetree endpoint from a cached stakeholder and perform the sidetree operation.

#### CRUD Operations

All CRUD operations are precisely the equivalent Sidetree operation, on a sidetree endpoint as determined by the process above.

<!-- 
Compare against:
- ION did method - essentially just sidetree on the bitcoin network
  - public, based on a global network, so it uses sidetree but has a different "meta" structure (no consortia, orgs, etc)
- did:web - uses .well-known to hold did docs
-->

