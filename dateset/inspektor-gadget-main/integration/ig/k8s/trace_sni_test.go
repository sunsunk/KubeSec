// Copyright 2022-2023 The Inspektor Gadget authors
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
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	sniTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/types"
)

func TestTraceSni(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-sni")

	traceSNICmd := &Command{
		Name:         "TraceSNI",
		Cmd:          fmt.Sprintf("ig trace sni -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			isDockerRuntime := *containerRuntime == ContainerRuntimeDocker
			isCrioRuntime := *containerRuntime == ContainerRuntimeCRIO
			expectedEntry := &sniTypes.Event{
				Event: BuildBaseEvent(ns,
					WithRuntimeMetadata(*containerRuntime),
					WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
					WithPodLabels("test-pod", ns, isCrioRuntime),
				),
				Comm: "wget",
				Name: "kubernetes.default.svc.cluster.local",
			}

			normalize := func(e *sniTypes.Event) {
				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (*containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
					e.Runtime.ContainerName = "test-pod"
				}

				e.Timestamp = 0
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				e.Runtime.ContainerID = ""
				e.Runtime.ContainerImageDigest = ""

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if isDockerRuntime {
					e.Runtime.ContainerImageName = ""
				}
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	}

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceSNICmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, "wget --no-check-certificate -T 2 -q -O /dev/null https://kubernetes.default.svc.cluster.local"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
