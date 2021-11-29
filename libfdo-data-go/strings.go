package libfdo_data

// #include <libfdo-data/fdo_data.h>
import "C"

func fromFDOString(c_string *C.char) string {
	newval := C.GoString(c_string)
	C.fdo_free_string(c_string)
	return newval
}
