# Endpoint Discovery Spec 0.1

This spec defines a conceptual infrastructure for the discovery of distributed service endpoints. Herein are defined a number of methods of endpoint discovery, to satisfy various use cases and governance models for a distributed service.

TODO: should the spec be defined strictly in terms of Sidetree?

TODO: should the spec be specifically about *consortium*-based endpoint discovery?

### Rationale

A distributed service can operate over a network of servers that are run by independent entities, with varying models of trust. A client of a distributed service needs to be able to determine the location of endpoints that it can send requests to, and needs to ensure some degree of trust in the identity and validity of these endpoints, and the validity of the APIs they provide.


### Definitions

**Endpoint Provider:** an organization which manages one or more servers that expose endpoints for the distributed service.

**Consortium:** a loose supra-organization formed where multiple independent endpoint providers, operating on the same network of a distributed service, agree to share custody of configuration data which clients can use to discover the endpoints of these providers. These endpoint providers are referred to as the *members* of the consortium, and operate a shared endorsement mechanism that clients can validate.

### The Consortium/Member Data Model

TODO: describe the system conceptually, the consortium data and the member-specific data, how it uses multiple endorsement, updates with static history, giving clients the ability to validate that the current state of a consortium can be trusted as a descendant of the initial state. 
- bring the Bootstrapping Trust and Configuration Updates sections from the did-method spec here wholesale, and split them into conceptual portions and normative specification portions
- in normative section: file formats, client-side validation procedures, and member-side operational procedures


