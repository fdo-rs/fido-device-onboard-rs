package libfdo_data

// #include <libfdo-data/fdo_data.h>
import "C"

import (
	"fmt"
)

type OwnershipVoucherList struct {
	inner *C.struct_FdoOwnershipVoucherList
}

func ParseManyOwnershipVouchers(voucherB []byte) (*OwnershipVoucherList, error) {
	ctslen := C.size_t(len(voucherB))
	cts := C.CBytes(voucherB)

	voucherlist := C.fdo_ownershipvoucher_many_from_data(cts, ctslen)
	if voucherlist == nil {
		return nil, fmt.Errorf("failed to parse ownership vouchers: %v", getLastError())
	}

	return &OwnershipVoucherList{
		inner: voucherlist,
	}, nil
}

func (ovl *OwnershipVoucherList) Free() {
	C.fdo_ownershipvoucher_list_free(ovl.inner)
}

func (ovl *OwnershipVoucherList) Len() int {
	return int(C.fdo_ownershipvoucher_list_len(ovl.inner))
}

func (ovl *OwnershipVoucherList) GetVoucher(index int) (*OwnershipVoucher, error) {
	item := C.fdo_ownershipvoucher_list_get(ovl.inner, C.uint64_t(index))
	if item == nil {
		return nil, fmt.Errorf("no voucher")
	}

	return &OwnershipVoucher{
		inner:       item,
		should_free: false,
	}, nil
}

type OwnershipVoucher struct {
	inner *C.struct_FdoOwnershipVoucher
	// Make sure that even if free is called on list items, we don't actually tell
	// rust to free the memory (that is owned by the list).
	should_free bool
}

func ParseOwnershipVoucher(voucherB []byte) (*OwnershipVoucher, error) {
	ctslen := C.size_t(len(voucherB))
	cts := C.CBytes(voucherB)

	voucher := C.fdo_ownershipvoucher_from_data(cts, ctslen)
	if voucher == nil {
		return nil, fmt.Errorf("failed to parse: %v", getLastError())
	}

	return &OwnershipVoucher{
		inner:       voucher,
		should_free: true,
	}, nil
}

func (ov *OwnershipVoucher) Free() {
	if ov.should_free {
		C.fdo_ownershipvoucher_free(ov.inner)
	}
}

func (ov *OwnershipVoucher) GetProtocolVersion() uint32 {
	return uint32(C.fdo_ownershipvoucher_header_get_protocol_version(ov.inner))
}

func (ov *OwnershipVoucher) GetGUID() string {
	return fromFDOString(C.fdo_ownershipvoucher_header_get_guid(ov.inner))
}

func (ov *OwnershipVoucher) GetDeviceInfo() string {
	return fromFDOString(C.fdo_ownershipvoucher_header_get_device_info_string(ov.inner))
}
