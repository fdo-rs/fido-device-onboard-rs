package libfdo_data

// #include <libfdo-data/fdo_data.h>
import "C"
import "fmt"

func getLastError() error {
	err := C.fdo_get_last_error()
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s", fromFDOString(err))
}
