# Terms

The words this project uses with one fixed meaning, one paragraph each. Code, issues and Specs use the same word; a new term is added here when it gets a fixed meaning.

**Attestation**: A device's one-time proof, at key creation, that its App Attest key was generated in the Secure Enclave of a genuine Apple device running a genuine copy of the app.

**Assertion**: A device's per-request proof, using an already-attested key, that the request comes from that same device.

**Counter**: A number that must strictly increase with every Assertion from a device, used to detect a captured Assertion being replayed.

**Risk metric**: Apple's own signal, fetched per device from its servers, estimating how many distinct devices have used the same attested key; informational only, never a reason to accept or reject.

**Device**: What a caller stores per attested key — its public key, Counter, environment and current Receipt — returned by an Attestation and moved on by every Assertion; app_attest itself never stores it.

**Key ID**: The name a device gives its own App Attest key, derived from the key itself, so a key can only be recorded under the one name it yields.

**Receipt**: Apple's signed record of a device's attested key, of one of two types: `ATTEST`, issued inside the Attestation, and `RECEIPT`, issued in exchange for the previous Receipt each time the Risk metric is read; only a `RECEIPT` carries the Risk metric.
