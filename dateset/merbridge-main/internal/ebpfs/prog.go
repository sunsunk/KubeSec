/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpfs

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
)

func LoadMBProgs(meshMode string, useReconnect, useCniMode, debug bool) error {
	if os.Getuid() != 0 {
		return fmt.Errorf("root user in required for this process or container")
	}
	cmd := exec.Command("make", "load")
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "MESH_MODE="+meshMode)
	if debug {
		cmd.Env = append(cmd.Env, "DEBUG=1")
	}
	if useReconnect {
		cmd.Env = append(cmd.Env, "USE_RECONNECT=1")
	}
	if useCniMode {
		cmd.Env = append(cmd.Env, "ENABLE_CNI_MODE=1")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("unexpected exit code: %d, err: %v", code, err)
	}
	return nil
}

func AttachMBProgs() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("root user in required for this process or container")
	}
	cmd := exec.Command("make", "attach")
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("unexpected exit code: %d, err: %v", code, err)
	}
	return nil
}

func UnLoadMBProgs() error {
	cmd := exec.Command("make", "-k", "clean")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("unload unexpected exit code: %d, err: %v", code, err)
	}
	return nil
}

var (
	ingress  *ebpf.Program
	egress   *ebpf.Program
	allocPid *ebpf.Program
	doExit   *ebpf.Program
)

func GetAllocPidProg() *ebpf.Program {
	if allocPid == nil {
		p, err := ebpf.LoadPinnedProgram("/sys/fs/bpf/mb_process/kretprobe_alloc_pid", &ebpf.LoadPinOptions{})
		if err != nil {
			log.Errorf("init kretprobe_alloc_pid prog error: %v", err)
		}
		allocPid = p
	}
	return allocPid
}

func GetDoExitProg() *ebpf.Program {
	if doExit == nil {
		p, err := ebpf.LoadPinnedProgram("/sys/fs/bpf/mb_process/kprobe_do_exit", &ebpf.LoadPinOptions{})
		if err != nil {
			log.Errorf("init kprobe_do_exit prog error: %v", err)
		}
		doExit = p
	}
	return doExit
}

func GetTCIngressProg() *ebpf.Program {
	if ingress == nil {
		err := initTCProgs()
		if err != nil {
			log.Errorf("init tc prog filed: %v", err)
		}
	}
	return ingress
}

func GetTCEgressProg() *ebpf.Program {
	if egress == nil {
		err := initTCProgs()
		if err != nil {
			log.Errorf("init tc prog filed: %v", err)
		}
	}
	return egress
}

func initTCProgs() error {
	coll, err := ebpf.LoadCollectionSpec("bpf/mb_tc.o")
	if err != nil {
		return err
	}
	type progs struct {
		Ingress *ebpf.Program `ebpf:"mb_tc_ingress"`
		Egress  *ebpf.Program `ebpf:"mb_tc_egress"`
	}
	ps := progs{}
	err = coll.LoadAndAssign(&ps, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"local_pod_ips":     GetLocalIPMap(),
			"pair_original_dst": GetPairOriginalMap(),
		},
	})
	if err != nil {
		return err
	}
	ingress = ps.Ingress
	egress = ps.Egress
	return nil
}
