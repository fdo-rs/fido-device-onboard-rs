package main

import (
	"fmt"
	"io/ioutil"
	"os"

	libfdo_data "github.com/fedora-iot/fido-device-onboard-rs/libfdo-data-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <ownershipvoucher.bin>\n", os.Args[0])
		os.Exit(1)
	}
	ctsB := []byte{}
	for _, arg := range os.Args[1:] {
		fileB, err := ioutil.ReadFile(arg)
		if err != nil {
			panic(err)
		}
		ctsB = append(ctsB, fileB...)
	}

	vouchers, err := libfdo_data.ParseManyOwnershipVouchers(ctsB)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer vouchers.Free()

	for i := 0; i < vouchers.Len(); i++ {
		fmt.Println("Device", i)

		voucher, err := vouchers.GetVoucher(i)
		if err != nil {
			panic(err)
		}

		protocol_version := voucher.GetProtocolVersion()
		guid := voucher.GetGUID()
		device_info := voucher.GetDeviceInfo()

		fmt.Println("\tProtocol version:", protocol_version)
		fmt.Println("\tDevice GUID:", guid)
		fmt.Println("\tDevice Info:", device_info)
	}
}
