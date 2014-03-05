package apparmor

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

var AppArmorEnabled bool

var (
	ErrAppArmorDisabled = errors.New("Error: AppArmor is not enabled on this system")
)

func init() {
	buf, err := ioutil.ReadFile("/sys/module/apparmor/parameters/enabled")
	AppArmorEnabled = err == nil && len(buf) > 1 && buf[0] == 'Y'
}

func ApplyProfile(pid int, name string) error {
	if !AppArmorEnabled {
		return ErrAppArmorDisabled
	}
	if name == "" {
		return nil
	}

	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/attr/current", pid), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "changeprofile %s", name); err != nil {
		return err
	}
	return nil
}
