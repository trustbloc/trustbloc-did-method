# Bloc DID Method Specification

## `did:bloc` Method Specification

### 

The `did:bloc` DID method allows groups of independent organizations to share custody of a DID registry on a permissioned ledger.

Independent *stakeholder* organizations which wish to transact with one another using DIDs can come together to form a *consortium* to manage their shared custody of a ledger.

Definitions:

- Consortium: a group of Stakeholder organizations which all manage DIDs with their own Sidetree nodes, all on the same ledger.
- Stakeholder organization (or just stakeholder): an independent organization which follows some cooperative rules with the other stakeholder organizations within the same consortium to allow them all to manage DIDs using their own Sidetree nodes on the same ledger. Stakeholders host ledger nodes, host sidetree endpoints, and sign policy changes.

#### `did:bloc` DID Format

A DID for the Block DID Method has the following format:

`did:bloc:[host]:[doc hash]`

Where `[host]` is a URL host (eg, `foo.example.net`) and `[doc hash]` is the document hash as used in Sidetree.

#### Consortium Data Model
The policies of a consortium, along with information identifying the stakeholders, is stored under the consortium's domain, within `http://[consortium domain]/.well-known/did-bloc`

`.well-known/did-bloc` should have this file hierarchy:

    .well-known/did-bloc/
        consortium/
            conf.json
        stakeholders/
        history/
    
##### The `consortium` directory
This directory contains the current consortium configuration, according to this particular server.

###### `conf.json`
The consortium config contains the following:
- The domain name of the consortium
- Consortium policy configuration settings
- A list of stakeholders - containing, for each stakeholder:
  - The web domain where its configuration can be found
  - A local hashlink to the cached stakeholder configuration
- A list of detached JWS signatures, from the stakeholders, on the config file
- A local hashlink to the previous version of this config file

###### Consortium Endorsement Signatures
Stakeholders endorse the contents of a consortium configuration file by signing the contents.

Verification: The signatures array must be removed from the config file and the config file must be canonicalized (TODO: define how) before the signatures are verified against the file.

##### Stakeholder Configurations
Within `stakeholders/` are files for stakeholder configs.

There must be at least one stakeholder config file here, for the consortium domain to be usable for resolving DIDs.

Each of these files is named `[hash].json`, where `hash` is the SHA-256 hash of the contents of the file. This hash value is the value used in the consortium config to link to this stakeholder config.

A stakeholder configuration file contains:
- The stakeholder's domain
- Stakeholder custom configuration settings
- The stakeholder's Sidetree endpoints
- A detached JWS signature on the file, created by the stakeholder
- a local hashlink to the previous version of this config file

TODO: Specify how the stakeholders are identified as the owners of the signing keys. For example, they could have DIDs, with the docs resolvable in the consortium (with some appropriate method of bootstrapping trust), or they could have x.509 certs.

##### History
The `history/` directory contains historical consortium configs. Each such file is named `[hash].json`, where `[hash]` is the SHA-256 hash of the given file.

<!--
TODO:
- Resolver has to check for consortium changes - how often?
  - update check frequency or cache lifetime should be part of the policy, or specified in the particular configuration file
- when the resolver hits stakeholders to verify the consortium policy config, if it finds that a stakeholder has a newer version of a file than the consortium, how does it respond?
 - update to the latest version that has sufficient endorsement?
--> 

### CRUD Operation Definitions

#### Finding a Sidetree Endpoint
Most operations require the resolver to process configuration files before finding Sidetree endpoints for DID operations. This always follows the same procedure:

- Given a bloc DID: `did:bloc:[hostname]:[hash]`
- Check local cache for fresh config files that provide sufficient sidetree endpoints for the operation
- If such files are available:
  - Select endpoints and submit operation 
- Otherwise:
  - Fetch `https://[hostname]/.well-known/did-bloc/consortium/conf.json`
  - Fetch stakeholder configurations
  - (Possibly) verify documents across multiple stakeholders
  - Cache documents
  - Select a sidetree endpoint to process the operation
    - Potentially select multiple endpoints across multiple organizations
  - Submit operation

#### Create (Register)
#### Read (Resolve)
#### Update
#### Delete (Revoke)
#### Recover


<!-- 
Compare against:
- ION did method - essentially just sidetree on the bitcoin network
  - public, based on a global network, so it uses sidetree but has a different "meta" structure (no consortia, orgs, etc)
- did:web - uses .well-known to hold did docs
-->

