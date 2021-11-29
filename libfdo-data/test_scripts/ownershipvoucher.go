package main

import (
	"fmt"
	"io/ioutil"
	"os"

	libfdo_data "github.com/fedora-iot/fido-device-onboard-rs/libfdo-data-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <ownershipvoucher.bin>\n", os.Args[0])
		os.Exit(1)
	}
	ctsB, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	voucher, err := libfdo_data.ParseOwnershipVoucher(ctsB)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer voucher.Free()

	protocol_version := voucher.GetProtocolVersion()
	guid := voucher.GetGUID()
	device_info := voucher.GetDeviceInfo()

	fmt.Println("Protocol version:", protocol_version)
	fmt.Println("Device GUID:", guid)
	fmt.Println("Device Info:", device_info)
}
