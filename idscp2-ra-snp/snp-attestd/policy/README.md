# snp-attestd Policies

snp-attestd policies are used to constrain the fields of the SEV-SNP attestation report.
Policies are provided to snp-attestd as an array of json objects.

Each policy object contains a `type` property determining the behavior of the policy.
It can also contain an `id` property providing additional context when an attestation report fails the policy check.
The policy also contains a `params` object, the structure of which depends on the policy type.

Internally, a policy is an implementation of the `Policy` interface defined in [policy.go](policy.go).
Each policy implementation must also provide and register a factory function that can construct the policy object from its parameters encoded as json.

A policy array may look like this:
```json
[
    {
        "type": "equals",
        "id": "Report has version 2",
        "params": {
            "field": "VERSION",
            "referenceValue": "AAAAAg=="
        }
    },
    {
        "type": "equals",
        "id": "Mesurement matches expected value",
        "params": {
            "field": "MEASUREMENT",
            "referenceValue": "30DT...U1n"
        }
    }
]
```

## Policy Types

snp-attestd currently implements the following policies:

### Equals

The Equals policy matches a field in the attestation report against a reference value.
The policy treats each field as little-endian encoded binary data.
The reference value should be encoded as base64.

An instance of the Equals policy looks like this:
```json
{
    "type": "equals",
    "params": {
        "field": "MEASUREMENT",
        "referenceValue": "AAAAA...AAAAA"
    }
}
```

### Greater Equal

The Greater Equal policy ensures that a field has at least the provided minimum value.
Values are compared as big-endian encoded byte arrays in order to preserve the order of numeric values.
As the values in the attestation report are all encoded as little endian, the reference value is expected to be so as well.

The Greater Equal policy looks like this:
```json
{
    "type": "greaterEqual",
    "params": {
        "field": "GUEST_SVN",
        "minimumValue": "AAAAAA=="
    }
}
```

### TCB Greater Equal

The TCP Greater Equal policy is used to ensure that all components of a TCB version are greater or equal to the provided reference values.

A TCB Greater Equal policy may look like this:
```json
{
    "type": "tcbGreaterEqual",
    "params": {
        "field": "CURRENT_TCB",
        "minBootLoaderVersion": 0,
        "minTEEVersion": 0,
        "minSNPVersion": 0,
        "minMicrocodeVersion": 0
    }
}
```