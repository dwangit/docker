// +build linux

package nsinit

import (
	"fmt"
	"github.com/dotcloud/docker/pkg/libcontainer"
	"github.com/dotcloud/docker/pkg/libcontainer/capabilities"
	"github.com/dotcloud/docker/pkg/libcontainer/network"
	"github.com/dotcloud/docker/pkg/libcontainer/utils"
	"github.com/dotcloud/docker/pkg/system"
	"github.com/dotcloud/docker/pkg/user"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// Init is the init process that first runs inside a new namespace to setup mounts, users, networking,
// and other options required for the new container.
func (ns *linuxNs) Init(container *libcontainer.Container, nspid int, uncleanRootfs, console string, syncPipe *SyncPipe, args []string) error {
	rootfs, err := utils.ResolveRootfs(uncleanRootfs)
	if err != nil {
		return err
	}

	// We always read this as it is a way to sync with the parent as well
	context, err := syncPipe.ReadFromParent()
	if err != nil {
		syncPipe.Close()
		return err
	}
	syncPipe.Close()

	////////////////////////////////////////////////////////////
	///////////////////////// WARNING //////////////////////////
	// we are duplicating the setup console code because      //
	// some crazy go thing is happening where it does not work//
	// if it is in a function                                 //
	////////////////////////////////////////////////////////////
	if nspid <= 0 {
		if console != "" {
			// close pipes so that we can replace it with the pty
			closeStdPipes()
			slave, err := system.OpenTerminal(console, syscall.O_RDWR)
			if err != nil {
				return fmt.Errorf("open terminal %s", err)
			}
			if err := dupSlave(slave); err != nil {
				return fmt.Errorf("dup2 slave %s", err)
			}
		}
		if _, err := system.Setsid(); err != nil {
			return fmt.Errorf("setsid %s", err)
		}
		if console != "" {
			if err := system.Setctty(); err != nil {
				return fmt.Errorf("setctty %s", err)
			}
		}
		if err := setupNewMountNamespace(rootfs, console, container.ReadonlyFs); err != nil {
			return fmt.Errorf("setup mount namespace %s", err)
		}
		if err := setupNetwork(container, context); err != nil {
			return fmt.Errorf("setup networking %s", err)
		}
		if err := system.Sethostname(container.Hostname); err != nil {
			return fmt.Errorf("sethostname %s", err)
		}
	} else {
		for _, ns := range container.Namespaces {
			if err := system.Unshare(ns.Value); err != nil {
				return err
			}
		}
		if console != "" {
			// close pipes so that we can replace it with the pty
			closeStdPipes()
			slave, err := system.OpenTerminal(console, syscall.O_RDWR)
			if err != nil {
				return fmt.Errorf("open terminal %s", err)
			}
			if err := dupSlave(slave); err != nil {
				return fmt.Errorf("dup2 slave %s", err)
			}
		}
		if _, err := system.Setsid(); err != nil {
			return fmt.Errorf("setsid %s", err)
		}
		if console != "" {
			if err := system.Setctty(); err != nil {
				return fmt.Errorf("setctty %s", err)
			}
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
				goto final
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
	}
final:
	if err := finalizeNamespace(container); err != nil {
		return fmt.Errorf("finalize namespace %s", err)
	}
	return system.Execv(args[0], args[0:], container.Env)
}

func closeStdPipes() {
	os.Stdin.Close()
	os.Stdout.Close()
	os.Stderr.Close()
}

func setupUser(container *libcontainer.Container) error {
	switch container.User {
	case "root", "":
		if err := system.Setgroups(nil); err != nil {
			return err
		}
		if err := system.Setresgid(0, 0, 0); err != nil {
			return err
		}
		if err := system.Setresuid(0, 0, 0); err != nil {
			return err
		}
	default:
		uid, gid, suppGids, err := user.GetUserGroupSupplementary(container.User, syscall.Getuid(), syscall.Getgid())
		if err != nil {
			return err
		}
		if err := system.Setgroups(suppGids); err != nil {
			return err
		}
		if err := system.Setgid(gid); err != nil {
			return err
		}
		if err := system.Setuid(uid); err != nil {
			return err
		}
	}
	return nil
}

// dupSlave dup2 the pty slave's fd into stdout and stdin and ensures that
// the slave's fd is 0, or stdin
func dupSlave(slave *os.File) error {
	if slave.Fd() != 0 {
		return fmt.Errorf("slave fd not 0 %d", slave.Fd())
	}
	if err := system.Dup2(slave.Fd(), 1); err != nil {
		return err
	}
	if err := system.Dup2(slave.Fd(), 2); err != nil {
		return err
	}
	return nil
}

// setupVethNetwork uses the Network config if it is not nil to initialize
// the new veth interface inside the container for use by changing the name to eth0
// setting the MTU and IP address along with the default gateway
func setupNetwork(container *libcontainer.Container, context libcontainer.Context) error {
	for _, config := range container.Networks {
		strategy, err := network.GetStrategy(config.Type)
		if err != nil {
			return err
		}
		return strategy.Initialize(config, context)
	}
	return nil
}

// finalizeNamespace drops the caps and sets the correct user
// and working dir before execing the command inside the namespace
func finalizeNamespace(container *libcontainer.Container) error {
	if err := capabilities.DropCapabilities(container); err != nil {
		return fmt.Errorf("drop capabilities %s", err)
	}
	if err := setupUser(container); err != nil {
		return fmt.Errorf("setup user %s", err)
	}
	if container.WorkingDir != "" {
		if err := system.Chdir(container.WorkingDir); err != nil {
			return fmt.Errorf("chdir to %s %s", container.WorkingDir, err)
		}
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
	}
	return fds, nil
}
