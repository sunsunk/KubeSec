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

package config

import (
	"flag"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kubernetes/test/e2e/framework"

	test "github.com/chaos-mesh/chaos-mesh/e2e-test"
)

// TestConfig for the test config
var TestConfig = test.NewDefaultConfig()

// RegisterOperatorFlags registers flags for chaos-mesh.
func RegisterOperatorFlags(flags *flag.FlagSet) {
	flags.StringVar(&TestConfig.ManagerImage, "manager-image-registry", "ghcr.io", "chaos-mesh image registry")
	flags.StringVar(&TestConfig.ManagerImage, "manager-image", "chaos-mesh/chaos-mesh", "chaos-mesh image")
	flags.StringVar(&TestConfig.ManagerTag, "manager-image-tag", "latest", "chaos-mesh image tag")
	flags.StringVar(&TestConfig.DaemonImage, "daemon-image-registry", "ghcr.io", "chaos-daemon image registry")
	flags.StringVar(&TestConfig.DaemonImage, "daemon-image", "chaos-mesh/chaos-daemon", "chaos-daemon image")
	flags.StringVar(&TestConfig.DaemonTag, "daemon-image-tag", "latest", "chaos-daemon image tag")
	flags.StringVar(&TestConfig.E2EImage, "e2e-image", "chaos-mesh/e2e-helper:latest", "e2e-helper image")
	flags.StringVar(&TestConfig.ChaosCoreDNSImage, "chaos-coredns-image", "chaos-mesh/chaos-coredns:v0.2.6", "chaos-coredns image")
	flags.StringVar(&TestConfig.PauseImage, "pause-image", "gcr.io/google-containers/pause:latest", "custom pause container image for pod failure chaos")
	flags.BoolVar(&TestConfig.InstallChaosMesh, "install-chaos-mesh", false, "automatically install chaos-mesh")
	flags.BoolVar(&TestConfig.EnableDashboard, "enable-dashboard", false, "enable Chaos Dashboard")
}

// LoadClientRawConfig would provide client raw config
func LoadClientRawConfig() (clientcmdapi.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = framework.TestContext.KubeConfig
	overrides := &clientcmd.ConfigOverrides{ClusterDefaults: clientcmd.ClusterDefaults}
	if framework.TestContext.KubeContext != "" {
		overrides.CurrentContext = framework.TestContext.KubeContext
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).RawConfig()
}
