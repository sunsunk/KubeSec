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
	dnsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newTraceDnsCmd(t *testing.T, ns string, dnsServerArgs string) *Command {
	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		PodCommand("dnstester", *dnsTesterImage, ns, `["/dnstester"]`, dnsServerArgs),
		WaitUntilPodReadyCommand(ns, "dnstester"),
	}

	RunTestSteps(commandsPreTest, t)

	t.Cleanup(func() {
		commands := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	dnsServer := GetTestPodIP(t, ns, "dnstester")
	nslookupCmds := []string{
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=a fake.test.com. %s", dnsServer),
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=aaaa fake.test.com. %s", dnsServer),
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=a nodomain.fake.test.com. %s", dnsServer),
	}
	// Start the busybox pod so that we can get the IP address of the pod.
	commands := []TestStep{
		BusyboxPodRepeatCommand(ns, strings.Join(nslookupCmds, " ; ")),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	busyBoxIP := GetTestPodIP(t, ns, "test-pod")
	traceDNSCmd := &Command{
		Name:         "TraceDns",
		Cmd:          fmt.Sprintf("ig trace dns -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			isDockerRuntime := *containerRuntime == ContainerRuntimeDocker
			isCrioRuntime := *containerRuntime == ContainerRuntimeCRIO
			expectedEntries := []*dnsTypes.Event{
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
						WithPodLabels("test-pod", ns, isCrioRuntime),
					),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					DstPort:    53,
					SrcIP:      busyBoxIP,
				},
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
						WithPodLabels("test-pod", ns, isCrioRuntime),
					),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Rcode:      "No Error",
					Latency:    1,
					NumAnswers: 1,
					Addresses:  []string{"127.0.0.1"},
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					SrcPort:    53,
					DstIP:      busyBoxIP,
				},
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
						WithPodLabels("test-pod", ns, isCrioRuntime),
					),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					DstPort:    53,
					SrcIP:      busyBoxIP,
				},
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
						WithPodLabels("test-pod", ns, isCrioRuntime),
					),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Rcode:      "No Error",
					Latency:    1,
					NumAnswers: 1,
					Addresses:  []string{"::1"},
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					SrcPort:    53,
					DstIP:      busyBoxIP,
				},
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
						WithPodLabels("test-pod", ns, isCrioRuntime),
					),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					DstPort:    53,
					SrcIP:      busyBoxIP,
				},
				{
					Event: BuildBaseEvent(ns,
						WithRuntimeMetadata(*containerRuntime),
						WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime),
						WithPodLabels("test-pod", ns, isCrioRuntime),
					),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "nodomain.fake.test.com.",
					QType:      "A",
					Rcode:      "Non-Existent Domain",
					Latency:    1,
					NumAnswers: 0,
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					SrcPort:    53,
					DstIP:      busyBoxIP,
				},
			}

			normalize := func(e *dnsTypes.Event) {
				// Docker and CRI-O use a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (*containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
					e.Runtime.ContainerName = "test-pod"
				}

				e.Timestamp = 0
				e.ID = ""
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				// Latency should be > 0 only for DNS responses.
				if e.Latency > 0 {
					e.Latency = 1
				}

				e.Runtime.ContainerID = ""
				e.Runtime.ContainerImageDigest = ""

				// Docker can provide different values for ContainerImageName. See `getContainerImageNamefromImage`
				if isDockerRuntime {
					e.Runtime.ContainerImageName = ""
				}

				if e.Qr == dnsTypes.DNSPktTypeResponse {
					e.DstPort = 0
					e.SrcIP = ""
				} else {
					e.SrcPort = 0
					e.DstIP = ""
				}
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
		},
	}

	return traceDNSCmd
}

func TestTraceDns(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-dns")

	// Start the trace gadget and verify the output.
	commands := []TestStep{
		newTraceDnsCmd(t, ns, ""),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestTraceDnsUncompress(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-dns-uncompress")

	// Start the trace gadget and verify the output.
	commands := []TestStep{
		newTraceDnsCmd(t, ns, "-uncompress"),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestTraceDnsHost(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-dns")

	commandsPreTest := []TestStep{
		CreateTestNamespaceCommand(ns),
		PodCommand("dnstester", *dnsTesterImage, ns, "", ""),
		WaitUntilPodReadyCommand(ns, "dnstester"),
	}

	RunTestSteps(commandsPreTest, t)
	dnsServer := GetTestPodIP(t, ns, "dnstester")

	traceDNSCmd := &Command{
		Name:         "TraceDnsHost",
		Cmd:          "ig trace dns -o json --host",
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntries := []*dnsTypes.Event{
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					// nslookup has several threads and isc-worker0000 will do the DNS
					// request.
					Comm:       "isc-worker0000",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Protocol:   "UDP",
					DstPort:    53,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Comm:       "isc-worker0000",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Protocol:   "UDP",
					DstPort:    53,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Comm:       "isc-worker0000",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Protocol:   "UDP",
					DstPort:    53,
				},
			}

			normalize := func(e *dnsTypes.Event) {
				e.Timestamp = 0
				e.ID = ""
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				// Latency should be > 0 only for DNS responses.
				if e.Latency > 0 {
					e.Latency = 1
				}

				e.SrcIP = ""
				e.SrcPort = 0
				e.DstIP = ""
				e.Runtime.ContainerImageDigest = ""
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
		},
	}

	cmd := fmt.Sprintf(`sh -c 'for i in $(seq 1 30); do nslookup -type=a fake.test.com. %s; nslookup -type=aaaa fake.test.com. %s; done'`, dnsServer, dnsServer)

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		traceDNSCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		&Command{
			Name:           cmd,
			Cmd:            cmd,
			ExpectedRegexp: dnsServer,
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
