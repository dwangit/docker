// +build linux

package nsinit

import (
	"fmt"
	"github.com/dotcloud/docker/pkg/libcontainer"
	"github.com/dotcloud/docker/pkg/system"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// ExecIn uses an existing pid and joins the pid's namespaces with the new command.
func (ns *linuxNs) joinExistingNamespace(container *libcontainer.Container, nspid int, console string, context libcontainer.Context) error {
	for _, ns := range container.Namespaces {
		if err := system.Unshare(ns.Value); err != nil {
			return err
		}
	}
	if err := ns.setupControllingTerminal(console); err != nil {
		return err
	}
	fds, err := ns.getNsFds(nspid, container)
	closeFds := func() {
		for _, f := range fds {
			system.Closefd(f)
		}
	}
	if err != nil {
		closeFds()
		return err
	}

	// foreach namespace fd, use setns to join an existing container's namespaces
	for _, fd := range fds {
		if fd > 0 {
			log.Printf("setns on %d\n", fd)
			if err := system.Setns(fd, 0); err != nil {
				closeFds()
				return fmt.Errorf("setns %s", err)
			}
		}
		system.Closefd(fd)
	}

	// if the container has a new pid and mount namespace we need to
	// remount proc and sys to pick up the changes
	if container.Namespaces.Contains("NEWNS") && container.Namespaces.Contains("NEWPID") {
		pid, err := system.Fork()
		if err != nil {
			return err
		}
		if pid == 0 {
			// TODO: make all raw syscalls to be fork safe
			if err := system.Unshare(syscall.CLONE_NEWNS); err != nil {
				return err
			}
			if err := remountProc(); err != nil {
				return fmt.Errorf("remount proc %s", err)
			}
			if err := remountSys(); err != nil {
				return fmt.Errorf("remount sys %s", err)
			}
			return nil
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			return err
		}
		state, err := proc.Wait()
		if err != nil {
			return err
		}
		os.Exit(state.Sys().(syscall.WaitStatus).ExitStatus())
	}
	return nil
}

func (ns *linuxNs) getNsFds(pid int, container *libcontainer.Container) ([]uintptr, error) {
	fds := make([]uintptr, len(container.Namespaces))
	for i, ns := range container.Namespaces {
		f, err := os.OpenFile(filepath.Join("/proc/", strconv.Itoa(pid), "ns", ns.File), os.O_RDONLY, 0)
		if err != nil {
			return fds, err
		}
		fds[i] = f.Fd()
		log.Printf("reading ns %s fd %d\n", ns.File, f.Fd())
	}
	return fds, nil
}
