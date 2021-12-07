// +build localbuild

package libfdo_data

// #cgo LDFLAGS: -lfdo_data -L../target/debug/
// #cgo CFLAGS: -I../
import "C"
