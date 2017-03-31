package main

import (
	"fmt"
	"github.com/dewaka/license_gen/lib"
	"time"
)

func main() {
	info := &lib.LiceseInfo{
		Name:       "Chathura",
		Expiration: time.Date(2017, time.July, 16, 0, 0, 0, 0, time.UTC),
	}

	if lib.CheckLicense(info, "test.lic") {
		fmt.Println("Ok")
	} else {
		fmt.Println("License check failed!")
	}
}
