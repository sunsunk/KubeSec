// Copyright 2021 Chaos Mesh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package e2e

import (
	"flag"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	runtimeutils "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"
	"k8s.io/kubernetes/test/e2e/framework/testfiles"

	_ "github.com/chaos-mesh/chaos-mesh/e2e-test/e2e/chaos"
	e2econfig "github.com/chaos-mesh/chaos-mesh/e2e-test/e2e/config" // test sources
)

// handleFlags sets up all flags and parses the command line.
func handleFlags() {
	config.CopyFlags(config.Flags, flag.CommandLine)
	framework.RegisterCommonFlags(flag.CommandLine)
	hackRegisterClusterFlags(flag.CommandLine)
	e2econfig.RegisterOperatorFlags(flag.CommandLine)
	flag.Parse()
}

func TestMain(m *testing.M) {
	// Register test flags, then parse flags.
	handleFlags()

	framework.AfterReadingAllFlags(&framework.TestContext)

	if framework.TestContext.RepoRoot != "" {
		testfiles.AddFileSource(testfiles.RootFileSource{Root: framework.TestContext.RepoRoot})
	}

	rand.Seed(time.Now().UnixNano())
	os.Exit(m.Run())
}

func TestE2E(t *testing.T) {
	RunE2ETests(t)
}

func RunE2ETests(t *testing.T) {
	runtimeutils.ReallyCrash = true
	logs.InitLogs()
	defer logs.FlushLogs()

	gomega.RegisterFailHandler(framework.Fail)

	// Run tests through the Ginkgo runner with output to console
	suite, _ := ginkgo.GinkgoConfiguration()
	klog.Infof("Starting e2e run %q on Ginkgo node %d", framework.RunID, suite.ParallelProcess)

	ginkgo.RunSpecs(t, "chaosmesh e2e suit")
}

// we hack framework.RegisterClusterFlags to avoid redefine flag error
// caused by controller-runtime client
func hackRegisterClusterFlags(flags *flag.FlagSet) {
	framework.TestContext.KubeConfig = os.Getenv("KUBECONFIG")
	if len(framework.TestContext.KubeConfig) < 1 {
		klog.Fatalf("KUBECONFIG ENV NOT SET")
	}
	flags.BoolVar(&framework.TestContext.VerifyServiceAccount, "e2e-verify-service-account", true, "If true tests will verify the service account before running.")
	flags.StringVar(&framework.TestContext.KubeContext, clientcmd.FlagContext, "", "kubeconfig context to use/override. If unset, will use value from 'current-context'")
	flags.StringVar(&framework.TestContext.KubeAPIContentType, "kube-api-content-type", "application/vnd.kubernetes.protobuf", "ContentType used to communicate with apiserver")

	flags.StringVar(&framework.TestContext.CertDir, "cert-dir", "", "Path to the directory containing the certs. Default is empty, which doesn't use certs.")
	flags.StringVar(&framework.TestContext.RepoRoot, "repo-root", "../../", "Root directory of kubernetes repository, for finding test files.")
	flags.StringVar(&framework.TestContext.Provider, "provider", "", "The name of the Kubernetes provider (gce, gke, local, skeleton (the fallback if not set), etc.)")
	flags.StringVar(&framework.TestContext.Tooling, "tooling", "", "The tooling in use (kops, gke, etc.)")
	flags.StringVar(&framework.TestContext.OutputDir, "e2e-output-dir", "/tmp", "Output directory for interesting/useful test data, like performance data, benchmarks, and other metrics.")
	flags.StringVar(&framework.TestContext.Prefix, "prefix", "e2e", "A prefix to be added to cloud resources created during testing.")
	flags.StringVar(&framework.TestContext.MasterOSDistro, "master-os-distro", "debian", "The OS distribution of cluster master (debian, ubuntu, gci, coreos, or custom).")
	flags.StringVar(&framework.TestContext.NodeOSDistro, "node-os-distro", "debian", "The OS distribution of cluster VM instances (debian, ubuntu, gci, coreos, or custom).")
	flags.StringVar(&framework.TestContext.ClusterDNSDomain, "dns-domain", "cluster.local", "The DNS Domain of the cluster.")

	flags.IntVar(&framework.TestContext.MinStartupPods, "minStartupPods", 0, "The number of pods which we need to see in 'Running' state with a 'Ready' condition of true, before we try running tests. This is useful in any cluster which needs some base pod-based services running before it can be used.")
	flags.StringVar(&framework.TestContext.EtcdUpgradeStorage, "etcd-upgrade-storage", "", "The storage version to upgrade to (either 'etcdv2' or 'etcdv3') if doing an etcd upgrade test.")
	flags.StringVar(&framework.TestContext.EtcdUpgradeVersion, "etcd-upgrade-version", "", "The etcd binary version to upgrade to (e.g., '3.0.14', '2.3.7') if doing an etcd upgrade test.")
	flags.StringVar(&framework.TestContext.GCEUpgradeScript, "gce-upgrade-script", "", "Script to use to upgrade a GCE cluster.")
	flags.BoolVar(&framework.TestContext.CleanStart, "clean-start", false, "If true, purge all namespaces except default and system before running tests. This serves to Cleanup test namespaces from failed/interrupted e2e runs in a long-lived cluster.")

	nodeKiller := &framework.TestContext.NodeKiller
	flags.BoolVar(&nodeKiller.Enabled, "node-killer", false, "Whether NodeKiller should kill any nodes.")
	flags.Float64Var(&nodeKiller.FailureRatio, "node-killer-failure-ratio", 0.01, "Percentage of nodes to be killed")
	flags.DurationVar(&nodeKiller.Interval, "node-killer-interval", 1*time.Minute, "Time between node failures.")
	flags.Float64Var(&nodeKiller.JitterFactor, "node-killer-jitter-factor", 60, "Factor used to jitter node failures.")
	flags.DurationVar(&nodeKiller.SimulatedDowntime, "node-killer-simulated-downtime", 10*time.Minute, "A delay between node death and recreation")
}
