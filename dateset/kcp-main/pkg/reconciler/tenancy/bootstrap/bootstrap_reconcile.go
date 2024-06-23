/*
Copyright 2022 The KCP Authors.

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

package bootstrap

import (
	"context"
	"time"

	"github.com/kcp-dev/logicalcluster/v3"

	"k8s.io/klog/v2"

	corev1alpha1 "github.com/kcp-dev/kcp/sdk/apis/core/v1alpha1"
	"github.com/kcp-dev/kcp/sdk/apis/tenancy/initialization"
)

func (c *controller) reconcile(ctx context.Context, workspace *corev1alpha1.LogicalCluster) error {
	logger := klog.FromContext(ctx)
	if workspace.Status.Phase != corev1alpha1.LogicalClusterPhaseInitializing {
		return nil
	}

	// have we done our work before?
	initializerName := initialization.InitializerForReference(c.workspaceType)
	if !initialization.InitializerPresent(initializerName, workspace.Status.Initializers) {
		return nil
	}

	// bootstrap resources
	clusterName := logicalcluster.From(workspace)
	logger.Info("bootstrapping resources for workspace", "cluster", clusterName)
	bootstrapCtx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second*30)) // to not block the controller
	defer cancel()

	if err := c.bootstrap(bootstrapCtx, c.kcpClusterClient.Cluster(clusterName.Path()).Discovery(), c.dynamicClusterClient.Cluster(clusterName.Path()), c.kcpClusterClient.Cluster(clusterName.Path()), c.batteriesIncluded); err != nil {
		return err // requeue
	}

	// we are done. remove our initializer
	workspace.Status.Initializers = initialization.EnsureInitializerAbsent(initializerName, workspace.Status.Initializers)

	return nil
}
