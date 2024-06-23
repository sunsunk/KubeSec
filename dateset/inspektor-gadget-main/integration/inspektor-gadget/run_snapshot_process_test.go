// Copyright 2023-2024 The Inspektor Gadget authors
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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestRunSnapshotProcess(t *testing.T) {
	t.Skip("not correctly handled by refactoring, yet (missing support for arrays as result)")
	ns := GenerateTestNamespaceName("test-run-snapshot-process")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -l -p 9090"),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commandsPostTest := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commandsPostTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	commands := []TestStep{
		&Command{
			Name:         "StartRunSnapshotProcessGadget",
			Cmd:          fmt.Sprintf("$KUBECTL_GADGET run %s/snapshot_process:%s -n %s -o json", *gadgetRepository, *gadgetTag, ns),
			StartAndStop: true,
			ValidateOutput: func(t *testing.T, output string) {
				expectedBaseJsonObj := RunEventToObj(t, &types.Event{
					CommonData: BuildCommonDataK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
				})

				expectedSnapshotProcessJsonObj := map[string]interface{}{
					"comm":     "nc",
					"uid":      0,
					"gid":      0,
					"pid":      0,
					"tid":      0,
					"ppid":     0,
					"mntns_id": 0,
				}

				expectedJsonObj := MergeJsonObjs(t, expectedBaseJsonObj, expectedSnapshotProcessJsonObj)

				normalize := func(m map[string]interface{}) {
					SetEventK8sNode(m, "")

					// TODO: Verify container runtime and container name
					SetEventRuntimeName(m, "")
					SetEventRuntimeContainerID(m, "")
					SetEventRuntimeContainerName(m, "")

					m["mntns_id"] = 0
					m["pid"] = uint32(0)
					m["tid"] = uint32(0)
					m["ppid"] = uint32(0)
				}

				ExpectEntriesInArrayToMatchObj(t, output, normalize, expectedJsonObj)
			},
		},
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
