---
layout: default
title: Full-Disk-Encryption configuration
parent: ServiceInfo Modules
---

## ServiceInfo Module for configuration full disk encryption

**STATUS: Draft**

This document specifies a Service-Info Module to be used for configuring Full-Disk Encryption (FDE) on the device filesystem, in this case using the Linux LUKS2 mechanism and binding the passphrase to Clevis.

The module name of this module during the TO2 protocol is *org.fedoraiot.diskencryption-clevis*.

### Owner Onboard Server to Device

| messageName | Value Type | Value/Message Meaning |
| --- | --- | --- |
| `disk-label` | `tstr` | The filesystem/Device Mapper label of the disk |
| `pin` | `tstr` | The name of the Clevis PIN |
| `config` | `tstr` | The JSON-encoded configuration for Clevis |
| `reencrypt` | `bool` | Whether or not to re-encrypt the disk |
| `execute` | `null` | This message triggers the initiation of the re-encryption and binding procedures |

### Device to Owner Onboard Server

| messageName | Value Type | Value/Message Meaning |
| --- | --- | --- |
| `disk-label` | `tstr` | The filesystem/Device Mapper label of the disk |
| `reencrypt-initiated` | `bool` | Indicates whether a re-encrypt has been initiated |
| `bound` | `bool` | Indicates whether rebinding to the new Clevis PIN completed successfully |
