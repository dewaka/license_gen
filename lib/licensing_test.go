package lib_test

import (
	"strings"
	"testing"
	"time"

	"github.com/dewaka/license_gen/lib"
)

var testLicense = `{
  "info": {
    "name": "Chathura Colombage",
    "expiration": "2017-07-16T00:00:00Z"
  },
  "key": "T7GkDY24W9mp9+usPmS46lN4sIEEtIVyVVnW7cslOBJyyWH2QLZCSN3vdkty4rg/CVgrUoGYJBAiFu5ku+lxxfK6W6I+6v6F/LENr8HFO+aBIN1MnGZcdVBdRHZKVTHJNmme4EDOJ4pv0eWNNP3h/ia4vzDuN/pRIcGxQn/DrjVK+cjn/6XGAaG6u1TmUTuN5XHJVnYphQ8jCN4C8W7TOlit/svcAWGybtQKouUk/491ckRtJxID+OTrQyW0mmZrBj/9Gsr1+Rpl/F1vjELUzImuTXHkFf1gyc35U/Ql2Qs+ys91VWc1wK8atnyHjazXCSs+/j83u+4D5QUTzxBnRQ=="
}
`

func TestReadLicense(t *testing.T) {
	r := strings.NewReader(testLicense)

	lic, err := lib.ReadLicense(r)
	if err != nil {
		t.Error("Error reading license file:", err)
	}

	if lic.Info.Name != "Chathura Colombage" {
		t.Error("Name does not match!")
	}

	if lic.Key == "" {
		t.Error("Key is empty!")
	}

	if lic.Info.Expiration != time.Date(2017, 7, 16, 0, 0, 0, 0, time.UTC) {
		t.Error("Expiration date is different!")
	}
}

func TestValidateKey(t *testing.T) {
	// t.Error("Write it!")
}
