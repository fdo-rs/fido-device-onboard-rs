---
layout: default
title: Device Initialize over Untrusted Networks
parent: Specifications
---

## Device Initialize Protocol over Untrusted Networks

**STATUS: Draft**


The FIDO Device Onboarding specification specifies the Device Initialize Protocol (section 5.2).
This protocol does not by itself provide enough information to initialize a device without prior agreement: it assumes the Manufacturer has received the public key of the device prior to the start of the protocol.
Additionally, the protocol has no security features other than possible transport security, which means that an attacker with local network access could man-in-the-middle the protocol.

To alleviate these issues, this specification adds some extra steps to the protocol to add the protections and information required.
Note specifically that after the extra steps from this protocol have been executed, the standard Device Initialization Protocol gets executed.

This protocol also implements support for proving in-band that a device private key is stored in a TPM with specific attributes.

*Note: at this moment, the attestation part is not included in this protocol. This will come in a later revision. This later revision WILL be incompatible with the current one.*


### Preparations

The Device ROE can be seeded with a hash of a public key to trust for the Device Initialize Protocol, `DIUNPubKeyHash`, or a list of trusted certificates `DIUNPubKeyRootCerts`, this is strongly adviced to perform.
This could also be left unconfigured, in which case the device operates under Trust On First Use.


### Protocol
#### Device-side preparation

The Device ROE starts preparing for the Device Initialize Protocol by generating a new private key for the Device key and a new hmac key for the Ownership Voucher hmac signing.
If the TPM extension is to be used, it also extracts the Endorsement Certificate out of the TPM.


#### Step 1: Connect, Type 210

**From Device ROE to Manufacturer**

The Connect message is sent to the Manufacturer to start the key exchange.

**Message format:**
``` cddl
DIUN.Connect = [
    NonceDiun1,
    KexSuiteName,
    CipherSuiteName,
    xAKeyExchange,
]

NonceDiun1 = Nonce
KexSuiteName = tstr
CipherSuiteName = tstr
xAKeyExchange = bstr
```

**HTTP Context:**
`POST /fdo/100/msg/210`

**Message Meaning:**
Initializes the protocol.
Starts the key exchange, by sending the information needed to perform one side
of the key exchange.


#### Step 2: Accept, Type 211

**From Manufacturer to Device ROE**

**Message format:**
``` cddl
DIUN.Accept = DIUNAcceptToken

;; DIUNAcceptToken is signed with the manufacturing server DIUN key.
;; The client does not have the public part of this key yet.
DIUNAcceptTokenUnprotectedHeaders = (
    CUPHOwnerPubKey: X5Chain,
)

DIUNAcceptTokenProtectedHeaders = (
    NonceDiun1: Nonce,
)

DIUNAcceptTokenPayload = DIUNAcceptPayload

DIUNAcceptPayload = [
    xBKeyExchange
]

xBKeyExchange = bstr
```

**Message Meaning:**
Provides the full DIUN public key, which the device can check against `DIUNPubKeyHash` if configured.
Includes the NonceDiun1 from DIUN.Connect, to prevent repeating.
Completes the key exchange, by sending xBKeyExchange.

Further messages in the DIUN and DI protocols are all encrypted and signed.


#### Step 3: Request Key Parameters, Type 212

**From Device ROE to Manufacturer**

**Message format - after decryption and verification:**
``` cddl
DIUN.RequestKeyParameters = [
    TenantId,
]

TenantId = null / tstr
```

**HTTP Context:**
`POST /fdo/100/msg/212`

**Message Meaning:**
Requests parameters for creating the device public key.


#### Step 4: Provide Key Parameters, Type 213

**From Manufacturer to Device ROE**

**Message Format - after decryption and verification:**
``` cddl
DIUN.ProvideKeyParameters = [
    pkType,
    KeyStorageTypes,
]

KeyStorageTypes = null / [ * KeyStorageType ]

KeyStorageType = (
    FileSystem: 0,
    Tpm:        1,
)
```

**Message Meaning:**
Provide the key type and key storage types that are acceptable to this manufacturing
server.
If no KeyStorageTypes are provided, the client can select any type of key storage
that it wants.


#### Step 5: Provide Key, Type 214

**From Device ROE to Manufacturer**

**Message Format - after decryption and verification:**
``` cddl
DIUN.ProvideKey = [
    PublicKey,
    KeyStorageType,
]
```

**HTTP Context:**
`POST /fdo/100/msg/214`

**Message Meaning:**
Provides the generated public key.


#### Step 6: Done, Type 215

**From Manufacturer to Device ROE**

**Message Format - after decryption and verification:**
``` cddl
DIUN.Done = [
    MfgStringType,
]

MfgStringType = (
    SerialNumber: 0,
)
```

**Message Meaning:**
Completes the protocol.
After this, the next message is `DI.AppStart`, from the standard Device Initialize protocol, but using the encryption from this protocol.
The manufacturer is expected to use the device public key that it received as part of this protocol.
The device is expected to send an MfgInfo that is indicated by the MfgStringType.
