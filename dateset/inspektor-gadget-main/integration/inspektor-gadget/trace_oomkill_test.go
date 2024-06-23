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

	traceoomkillTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceOOMKill(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-oomkill")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	traceOomkillCmd := &Command{
		Name:         "StartOomkilGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace oomkill -n %s -o json", ns),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &traceoomkillTypes.Event{
				Event:      BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
				KilledComm: "tail",
			}
			expectedEntry.K8s.ContainerName = "test-pod-container"

			normalize := func(e *traceoomkillTypes.Event) {
				e.Timestamp = 0
				e.KilledPid = 0
				e.Pages = 0
				e.TriggeredPid = 0
				e.TriggeredUid = 0
				e.TriggeredGid = 0
				e.TriggeredComm = ""
				e.MountNsID = 0

				e.K8s.Node = ""
				// TODO: Verify container runtime and container name
				e.Runtime.RuntimeName = ""
				e.Runtime.ContainerName = ""
				e.Runtime.ContainerID = ""
				e.Runtime.ContainerImageDigest = ""
			}

			ExpectAllToMatch(t, output, normalize, expectedEntry)
		},
	}

	limitPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
  labels:
    run: test-pod
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: test-pod-container
    image: busybox
    resources:
      limits:
        memory: "128Mi"
    command: ["/bin/sh", "-c"]
    args:
    - while true; do tail /dev/zero; done
`, ns)

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceOomkillCmd,
		&Command{
			Name:           "RunOomkillTestPod",
			Cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", limitPodYaml),
			ExpectedRegexp: "pod/test-pod created",
		},
		WaitUntilTestPodReadyOrOOMKilledCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
