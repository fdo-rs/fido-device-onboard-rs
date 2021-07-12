# Device Initialize Protocol over Untrusted Networks

**STATUS: Draft**


The FIDO Device Onboarding specification specifies the Device Initialize Protocol (section 5.2).
This protocol does not by itself provide enough information to initialize a device without prior agreement: it assumes the Manufacturer has received the public key of the device prior to the start of the protocol.
Additionally, the protocol has no security features other than a possible transport security, which means that an attacker with local network access could man-in-the-middle the protocol.

To alleviate these issues, this specification adds some extra steps to the protocol to add the protections and information required.
Note specifically that after the extra steps from this protocol have been executed, the standard Device Initialization Protocol gets executed.

This protocol also implements support for proving in-band that a device private key is stored in a TPM with specific attributes.


## Preparations

The Device ROE can be seeded with a hash of a public key to trust for the Device Initialize Protocol, `DIUNPubKeyHash`, this is strongly adviced to perform.
This could also be left unconfigured, in which case the device operates under Trust On First Use.


## Protocol
### Device-side preparation

The Device ROE starts preparing for the Device Initialize Protocol by generating a new private key for the Device key and a new hmac key for the Ownership Voucher hmac signing.
If the TPM extension is to be used, it also extracts the Endorsement Certificate out of the TPM.


### Step 1: Connect

**From Device ROE to Manufacturer**

The Connect message is sent to the Manufacturer to start the key exchange.

**Message format:**
``` cddl
DIUN.Connect = [
    xAKeyExchange
]
```

**HTTP Context:**
`POST /fdo/100/msg/210`

**Message Meaning:**
Initializes the protocol.
Starts the key exchange, by sending xAKeyExchange.


### Step 2: Accept

**From Manufacturer to Device ROE**

**Message format:**
``` cddl
DIUN.Accept = [
    DIUN_PubKey,
    DIUNAcceptPayload
]

DIUN_PubKey = PublicKey
;; DIUNAcceptPayload is signed by the DIUN Pubkey provided in DIUN.Accept.
DIUNAcceptPayload = CoseSignature
DIUNAcceptPayloadPayload = [
    xBKeyExchange
]
```

**Message Meaning:**
Provides the full DIUN public key, which the device can check against `DIUNPubKeyHash` if configured.
Completes the key exchange, by sending xBKeyExchange.

Further messages in the DIUN and DI protocols are all encrypted and signed.


### Step 3: Provide Key

**From Device ROE to Manufacturer**

**Message format - after decryption and verification:**
``` cddl
DIUN.ProvideKey = [
    DevicePublicKey,
    DevicePublicKeyProof,
]

DevicePublicKey = PublicKey
DevicePublicKeyProof = null / DevicePublicKeyProofData
DevicePublicKeyProofData = [
    DevicePublicKeyProofType,
    DevicePublicKeyProofValue
]
DevicePublicKeyProofType = tstr
DevicePublicKeyProofValue = cborSimpleType
```

**HTTP Context:**
`POST /fdo/100/msg/211`

**Message Meaning:**
Provides the Device public key, and information on how to prove it is the device's public key.
DevicePublicKeyProofType needs to be of a type that the Manufacturer can verify.
Currenlty only `tpm` is supported.
If no proof is provided, the value of `DevicePublicKeyProof` is `null`.


### Step 4: Request Attestation

**From Manufacturer to Device ROE**

**Message Format - after decryption and verification:**
``` cddl
DIUN.RequestAttestation = [
    KeyAttestationChallenge
]

KeyAttestationChallenge = null / bstr
```

**Message Meaning:**
Provides a challenge to the Device to prove that the public key is of the claimed type.
If no challenge is required, the value of `KeyAttestationChallenge` is `null`.


### Step 5: Attestation

**From Device ROE to Manufacturer**

**Message Format - after decryption and verification:**
``` cddl
DIUN.ProvideAttestation = [
    KeyAttestationResponse
]

KeyAttestationResponse = null / bstr
```

**HTTP Context:**
`POST /fdo/100/msg/212`

**Message Meaning:**
Provides the response to the key attestation challenge.
If no response is provided, the value of `KeyAttestationResponse` is `null`.


### Step 6: Done

**From Manufacturer to Device ROE**

**Message Format - after decryption and verification:**
``` cddl
DIUN.Done = []
```

**Message Meaning:**
Completes the protocol.
After this, the next message is `DI.AppStart`, from the standard Device Initialize protocol, but using the encryption from this protocol.
The manufacturer is expected to use the device public key that it received as part of this protocol.
