package common

import (
	"fmt"
	"strings"
)

func PhoneNumberPrefix(phone string) (validPhone string, err error) {
	validPhone = phone

	if !(strings.HasPrefix(phone, "0") ||
		strings.HasPrefix(phone, "62") ||
		strings.HasPrefix(phone, "+62")) {
		err = fmt.Errorf("invalid prefix")
	}

	zeroPrefix := strings.HasPrefix(phone, "0")
	if zeroPrefix {
		validPhone = strings.Replace(phone, "0", "+62", 1)
	}
	noPlusPrefix := strings.HasPrefix(phone, "62")
	if noPlusPrefix {
		validPhone = strings.Replace(phone, "62", "+62", 1)
	}
	return
}
