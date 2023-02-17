#ifndef FDO_DATA_H
#define FDO_DATA_H

#pragma once

/* This file is automatically generated, do not modify */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define FDO_DATA_MAJOR 0
#define FDO_DATA_MINOR 4
#define FDO_DATA_PATCH 8

typedef struct FdoOwnershipVoucher FdoOwnershipVoucher;

/**
 * A list of Ownership Vouchers
 */
typedef struct FdoOwnershipVoucherList FdoOwnershipVoucherList;

/**
 * Free a string returned by libfdo-data functions
 */
void fdo_free_string(char *s);

/**
 * Returns a string describing the last error that occurred
 *
 * Note: The returned string ownership is transferred to the caller, and should
 * be freed with `fdo_free_string`
 */
char *fdo_get_last_error(void);

/**
 * Returns a single Ownership Voucher from a list of Ownership Vouchers
 *
 * Note: the return Ownership Voucher is still owned by the list, and should
 * *NOT* be freed by the caller.
 *
 * Return value:
 * NULL if index is out of bounds
 * Pointer to an OwnershipVoucher on success
 */
const struct FdoOwnershipVoucher *fdo_ownershipvoucher_list_get(const struct FdoOwnershipVoucherList *list,
                                                                uint64_t index);

/**
 * Returns the length of an Ownership Voucher List
 */
uint64_t fdo_ownershipvoucher_list_len(const struct FdoOwnershipVoucherList *list);

/**
 * Frees an Ownership Voucher List
 */
void fdo_ownershipvoucher_list_free(struct FdoOwnershipVoucherList *list);

/**
 * Creates an Ownership Voucher List from raw data of appended vouchers
 *
 * Return value:
 * NULL on error (last error is set)
 * Pointer to an OwnershipVoucherList on success
 */
const struct FdoOwnershipVoucherList *fdo_ownershipvoucher_many_from_data(const void *data,
                                                                          size_t len);

/**
 * Creates a new OwnershipVoucher from raw data
 *
 * Return value:
 * NULL on error (last error is set)
 * Pointer to an FdoOwnershipVoucher on success
 */
struct FdoOwnershipVoucher *fdo_ownershipvoucher_from_data(const void *data, size_t len);

/**
 * Frees an OwnershipVoucher
 */
void fdo_ownershipvoucher_free(struct FdoOwnershipVoucher *v);

/**
 * Returns the protocol version in the ownership voucher
 *
 * Return value:
 * -1 on error (last error is set)
 * protocol version on success
 */
int32_t fdo_ownershipvoucher_header_get_protocol_version(const struct FdoOwnershipVoucher *v);

/**
 * Returns the GUID of the ownership voucher
 *
 * Return value:
 * NULL on error (last error is set)
 * Pointer to a string containing the GUID on success
 *
 * Note: The returned string ownership is transferred to the caller, and should
 * be freed with `fdo_free_string`
 */
const char *fdo_ownershipvoucher_header_get_guid(const struct FdoOwnershipVoucher *v);

/**
 * Returns the device info of the ownership voucher if it is a string
 *
 * Return value:
 * NULL on error or if Device Info is not a string
 * Pointer to a string containing the Device Info on success
 *
 * Note: The returned string ownership is transferred to the caller, and should
 * be freed with `fdo_free_string`
 */
const char *fdo_ownershipvoucher_header_get_device_info_string(const struct FdoOwnershipVoucher *v);

#endif /* FDO_DATA_H */
