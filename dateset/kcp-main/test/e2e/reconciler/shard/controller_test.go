/*
Copyright 2021 The KCP Authors.

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

package workspaceshard

import (
	"context"
	"testing"

	kcpkubernetesclientset "github.com/kcp-dev/client-go/kubernetes"
	"github.com/stretchr/testify/require"

	"k8s.io/client-go/kubernetes"

	"github.com/kcp-dev/kcp/sdk/apis/core"
	kcpclientset "github.com/kcp-dev/kcp/sdk/client/clientset/versioned/cluster"
	corev1alpha1client "github.com/kcp-dev/kcp/sdk/client/clientset/versioned/typed/core/v1alpha1"
	"github.com/kcp-dev/kcp/test/e2e/framework"
)

func TestWorkspaceShardController(t *testing.T) {
	t.Parallel()
	framework.Suite(t, "control-plane")

	type runningServer struct {
		framework.RunningServer
		rootShardClient               corev1alpha1client.ShardInterface
		rootKubeClient, orgKubeClient kubernetes.Interface
		expect                        framework.RegisterWorkspaceShardExpectation
	}
	var testCases = []struct {
		name        string
		destructive bool
		work        func(ctx context.Context, t *testing.T, server runningServer)
	}{
		// nothing for now
	}

	sharedServer := framework.SharedKcpServer(t)

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancelFunc := context.WithCancel(context.Background())
			t.Cleanup(cancelFunc)

			server := sharedServer
			if testCase.destructive {
				// Destructive tests require their own server
				//
				// TODO(marun) Could the testing currently requiring destructive e2e be performed with less cost?
				server = framework.PrivateKcpServer(t)
			}

			cfg := server.BaseConfig(t)

			orgPath, _ := framework.NewOrganizationFixture(t, server)

			kcpClient, err := kcpclientset.NewForConfig(cfg)
			require.NoError(t, err)

			expecterClient, err := kcpclientset.NewForConfig(server.RootShardSystemMasterBaseConfig(t))
			require.NoError(t, err)

			expect, err := framework.ExpectWorkspaceShards(ctx, t, expecterClient.Cluster(orgPath))
			require.NoError(t, err, "failed to start expecter")

			kubeClient, err := kcpkubernetesclientset.NewForConfig(cfg)
			require.NoError(t, err, "failed to construct kube rootShardClient for server")

			testCase.work(ctx, t, runningServer{
				RunningServer:   server,
				rootShardClient: kcpClient.Cluster(core.RootCluster.Path()).CoreV1alpha1().Shards(),
				rootKubeClient:  kubeClient.Cluster(core.RootCluster.Path()),
				orgKubeClient:   kubeClient.Cluster(orgPath),
				expect:          expect,
			})
		})
	}
}
