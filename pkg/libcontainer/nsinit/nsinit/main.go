package main

import (
	"encoding/json"
	"flag"
	"github.com/dotcloud/docker/pkg/libcontainer"
	"github.com/dotcloud/docker/pkg/libcontainer/nsinit"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

var (
	root, console string
	pipeFd, nspid int
)

func registerFlags() {
	flag.StringVar(&console, "console", "", "console (pty slave) path")
	flag.IntVar(&pipeFd, "pipe", 0, "sync pipe fd")
	flag.StringVar(&root, "root", ".", "root for storing configuration data")
	flag.IntVar(&nspid, "nspid", 0, "existing namespace pid")

	flag.Parse()
}

func main() {
	registerFlags()

	if flag.NArg() < 1 {
		log.Fatalf("wrong number of argments %d", flag.NArg())
	}
	container, err := loadContainer()
	if err != nil {
		log.Fatal(err)
	}
	ns, err := newNsInit()
	if err != nil {
		log.Fatal(err)
	}

	switch flag.Arg(0) {
	case "exec": // this is executed outside of the namespace in the cwd
		var exitCode int
		nspid, err := readPid()
		if err != nil {
			if !os.IsNotExist(err) {
				log.Fatal(err)
			}
		}
		term := nsinit.NewTerminal(os.Stdin, os.Stdout, os.Stderr, container.Tty)
		if exitCode, err = ns.Exec(container, nspid, term, flag.Args()[1:]); err != nil {
			log.Fatal(err)
		}
		os.Exit(exitCode)
	case "init": // this is executed inside of the namespace to setup the container
		f, err := os.OpenFile("/tmp/init.log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0755)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(f)

		log.Printf("in init with pid %d and pipe %d and log %d\n", nspid, pipeFd, f.Fd())

		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		if flag.NArg() < 2 {
			log.Fatalf("wrong number of argments %d", flag.NArg())
		}
		var syncPipe *nsinit.SyncPipe
		if pipeFd > 0 {
			if syncPipe, err = nsinit.NewSyncPipeFromFd(0, uintptr(pipeFd)); err != nil {
				log.Fatal(err)
			}
		}
		if err := ns.Init(container, nspid, cwd, console, syncPipe, flag.Args()[1:]); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("command not supported for nsinit %s", flag.Arg(0))
	}
}

func loadContainer() (*libcontainer.Container, error) {
	f, err := os.Open(filepath.Join(root, "container.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var container *libcontainer.Container
	if err := json.NewDecoder(f).Decode(&container); err != nil {
		return nil, err
	}
	return container, nil
}

func readPid() (int, error) {
	data, err := ioutil.ReadFile(filepath.Join(root, "pid"))
	if err != nil {
		return -1, err
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return -1, err
	}
	return pid, nil
}

func newNsInit() (nsinit.NsInit, error) {
	return nsinit.NewNsInit(&nsinit.DefaultCommandFactory{root}, &nsinit.DefaultStateWriter{root}), nil
}
