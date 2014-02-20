package main

import (
	"fmt"
	"github.com/dotcloud/docker/pkg/libcontainer"
	"github.com/dotcloud/docker/pkg/libcontainer/network"
	"github.com/dotcloud/docker/pkg/libcontainer/utils"
	"github.com/dotcloud/docker/pkg/system"
	"github.com/dotcloud/docker/pkg/term"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
)

func execCommand(container *libcontainer.Container) (int, error) {
	master, console, err := createMasterAndConsole()
	if err != nil {
		return -1, err
	}

	command := exec.Command("nsinit", "init", console)
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(getNamespaceFlags(container.Namespaces) | syscall.CLONE_VFORK), // we need CLONE_VFORK so we can wait on the child
	}

	inPipe, err := command.StdinPipe()
	if err != nil {
		return -1, err
	}
	if err := command.Start(); err != nil {
		return -1, err
	}
	if err := writePidFile(command); err != nil {
		return -1, err
	}

	if container.Network != nil {
		name1, name2, err := createVethPair()
		if err != nil {
			return -1, err
		}
		if err := network.SetInterfaceMaster(name1, container.Network.Bridge); err != nil {
			return -1, err
		}
		if err := network.InterfaceUp(name1); err != nil {
			return -1, err
		}
		if err := network.SetInterfaceInNamespacePid(name2, command.Process.Pid); err != nil {
			return -1, err
		}
		fmt.Fprint(inPipe, name2)
		inPipe.Close()
	}

	go io.Copy(os.Stdout, master)
	go io.Copy(master, os.Stdin)

	ws, err := term.GetWinsize(os.Stdin.Fd())
	if err != nil {
		return -1, err
	}
	if err := term.SetWinsize(master.Fd(), ws); err != nil {
		return -1, err
	}
	state, err := term.SetRawTerminal(os.Stdin.Fd())
	if err != nil {
		command.Process.Kill()
		return -1, err
	}
	defer term.RestoreTerminal(os.Stdin.Fd(), state)

	if err := command.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return -1, err
		}
	}
	return command.ProcessState.Sys().(syscall.WaitStatus).ExitStatus(), nil
}

func createMasterAndConsole() (*os.File, string, error) {
	master, err := os.OpenFile("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	console, err := system.Ptsname(master)
	if err != nil {
		return nil, "", err
	}
	if err := system.Unlockpt(master); err != nil {
		return nil, "", err
	}
	return master, console, nil
}

func createVethPair() (name1 string, name2 string, err error) {
	name1, err = utils.GenerateRandomName("dock", 4)
	if err != nil {
		return
	}
	name2, err = utils.GenerateRandomName("dock", 4)
	if err != nil {
		return
	}
	if err = network.CreateVethPair(name1, name2); err != nil {
		return
	}
	return
}

func writePidFile(command *exec.Cmd) error {
	return ioutil.WriteFile(".nspid", []byte(fmt.Sprint(command.Process.Pid)), 0655)
}
