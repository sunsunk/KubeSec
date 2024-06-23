// Copyright 2019-2022 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"testing"

	traceopenTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceOpen(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-open")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	traceOpenCmd := &Command{
		Name:         "StartTraceOpenGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace open -n %s -o json", ns),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &traceopenTypes.Event{
				Event:    BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
				Comm:     "cat",
				Fd:       3,
				Ret:      3,
				Err:      0,
				Path:     "/dev/null",
				FullPath: "",
				Uid:      1000,
				Gid:      1111,
				Flags:    []string{"O_RDONLY"},
				Mode:     "----------",
			}

			normalize := func(e *traceopenTypes.Event) {
				e.Timestamp = 0
				e.MountNsID = 0
				e.Pid = 0

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime.RuntimeName = ""
				e.Runtime.ContainerName = ""
				e.Runtime.ContainerID = ""
				e.Runtime.ContainerImageDigest = ""
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceOpenCmd,
		BusyboxPodRepeatCommand(ns, "setuidgid 1000:1111 cat /dev/null"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
