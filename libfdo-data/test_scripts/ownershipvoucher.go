package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

// #cgo LDFLAGS: -lfdo_data -L../../target/debug/
// #include "../fdo_data.h"
import "C"

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <ownershipvoucher.bin>\n", os.Args[0])
		os.Exit(1)
	}
	ctsB, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	ctslen := C.size_t(len(ctsB))
	cts := C.CBytes(ctsB)

	voucher := C.fdo_ownershipvoucher_from_data(cts, ctslen)
	if voucher == nil {
		fmt.Println("Failed to parse")
		return
	}
	defer C.fdo_ownershipvoucher_free(voucher)

	fmt.Println("Protocol version:", C.fdo_ownershipvoucher_header_get_protocol_version(voucher))

	guidS := C.fdo_ownershipvoucher_header_get_guid(voucher)
	defer C.fdo_free_string(guidS)
	guid := C.GoString(guidS)
	fmt.Println("Device GUID:", guid)

	devinfoS := C.fdo_ownershipvoucher_header_get_device_info_string(voucher)
	defer C.fdo_free_string(devinfoS)
	devinfo := C.GoString(devinfoS)
	fmt.Println("Device Info:", devinfo)
}
