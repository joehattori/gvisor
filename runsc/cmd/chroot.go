// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/specutils"
)

// mountInChroot creates the destination mount point in the given chroot and
// mounts the source.
func mountInChroot(chroot, src, dst, typ string, flags uint32) error {
	chrootDst := filepath.Join(chroot, dst)
	log.Infof("Mounting %q at %q", src, chrootDst)

	if err := specutils.Mount(src, chrootDst, typ, flags); err != nil {
		return fmt.Errorf("error mounting %q at %q: %v", src, chrootDst, err)
	}
	return nil
}

func pivotRoot(root string) error {
	if err := os.Chdir(root); err != nil {
		return fmt.Errorf("error changing working directory: %v", err)
	}
	// pivot_root(new_root, put_old) moves the root filesystem (old_root)
	// of the calling process to the directory put_old and makes new_root
	// the new root filesystem of the calling process.
	//
	// pivot_root(".", ".") makes a mount of the working directory the new
	// root filesystem, so it will be moved in "/" and then the old_root
	// will be moved to "/" too. The parent mount of the old_root will be
	// new_root, so after umounting the old_root, we will see only
	// the new_root in "/".
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root failed, make sure that the root mount has a parent: %v", err)
	}

	// JOETODO: delete here
	// walkDir := func(path string) {
	// files, err := ioutil.ReadDir(path)
	// if err != nil {
	// log.Infof("Wasm chroot no such dir %v", path)
	// return
	// }
	// log.Infof("Wasm chroot walking %v", path)
	// for _, f := range files {
	// log.Infof("Wasm chroot %v", f.Name())
	// }
	// }
	// walkDir("/rustfer")

	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("error umounting the old root file system: %v", err)
	}
	return nil
}

// setUpChroot creates an empty directory with runsc mounted at /runsc and proc
// mounted at /proc.
func setUpChroot(pidns bool) error {
	// We are a new mount namespace, so we can use /tmp as a directory to
	// construct a new root.
	chroot := os.TempDir()

	log.Infof("Setting up sandbox chroot in %q", chroot)

	// Convert all shared mounts into slave to be sure that nothing will be
	// propagated outside of our namespace.
	if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("error converting mounts: %v", err)
	}

	if err := unix.Mount("runsc-root", chroot, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("error mounting tmpfs in choot: %v", err)
	}

	if pidns {
		flags := uint32(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY)
		if err := mountInChroot(chroot, "proc", "/proc", "proc", flags); err != nil {
			return fmt.Errorf("error mounting proc in chroot: %v", err)
		}
	} else {
		if err := mountInChroot(chroot, "/proc", "/proc", "bind", unix.MS_BIND|unix.MS_RDONLY|unix.MS_REC); err != nil {
			return fmt.Errorf("error mounting proc in chroot: %v", err)
		}
	}

	// JOETODO: serialize module instead of reading it from wasm.
	rustferFilePath := "/home/vagrant/gvisor/rustfer/target/wasm32-wasi/release"
	flags := uint32(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY | unix.MS_REC | unix.MS_BIND)
	if err := mountInChroot(chroot, rustferFilePath, "/rustfer", "bind", flags); err != nil {
		return fmt.Errorf("error mounting rustfer in chroot: %v", err)
	}

	cw, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current directory %v", err)
	}
	if err := mountInChroot(chroot, cw, "/config", "bind", flags); err != nil {
		return fmt.Errorf("error mouting config in chroot: %v", err)
	}

	if err := os.Mkdir(filepath.Join(chroot, "/etc"), 0700); err != nil {
		return fmt.Errorf("error creating /etc in chroot: %v", err)
	}

	if err := ioutil.WriteFile(filepath.Join(chroot, "/etc/resolv.conf"), []byte("nameserver 8.8.8.8\n"), 0666); err != nil {
		return fmt.Errorf("error writing to /etc/resolv.conf: %v", err)
	}

	if err := ioutil.WriteFile(filepath.Join(chroot, "/etc/hostname"), []byte(cid+"\n"), 0600); err != nil {
		return fmt.Errorf("error writing to /etc/hostname: %v", err)
	}

	hosts := fmt.Sprintf("127.0.0.1\tlocalhost\n%s\t%s\n", "192.168.10.2", cid)
	if err := ioutil.WriteFile(filepath.Join(chroot, "/etc/hosts"), []byte(hosts), 0600); err != nil {
		return fmt.Errorf("error writing to /etc/hostname: %v", err)
	}

	if err := unix.Mount("", chroot, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("error remounting chroot in read-only: %v", err)
	}

	return pivotRoot(chroot)
}

func readETCMounts(bundleDir string) (mounts []specs.Mount, err error) {
	var bytes []byte
	bytes, err = ioutil.ReadFile(filepath.Join(bundleDir, "/config.json"))
	if err != nil {
		return
	}
	spec := &specs.Spec{}
	if err = json.Unmarshal(bytes, spec); err != nil {
		return
	}
	for _, m := range spec.Mounts {
		if strings.HasPrefix(m.Destination, "/etc") {
			mounts = append(mounts, m)
		}
	}
	return
}
