/*
Copyright 2023 The KCP Authors.

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

package replicateclusterrolebinding

import (
	kcprbacinformers "github.com/kcp-dev/client-go/informers/rbac/v1"
	kcpkubernetesclientset "github.com/kcp-dev/client-go/kubernetes"
	"github.com/kcp-dev/logicalcluster/v3"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/kcp-dev/kcp/pkg/reconciler/cache/labelclusterrolebindings"
	replicateclusterrole "github.com/kcp-dev/kcp/pkg/reconciler/tenancy/replicateclusterrole"
	"github.com/kcp-dev/kcp/sdk/apis/tenancy"
)

const (
	ControllerName = "kcp-tenancy-replicate-clusterrolebinding"
)

// NewController returns a new controller for labelling ClusterRoleBinding that should be replicated.
func NewController(
	kubeClusterClient kcpkubernetesclientset.ClusterInterface,
	clusterRoleBindingInformer kcprbacinformers.ClusterRoleBindingClusterInformer,
	clusterRoleInformer kcprbacinformers.ClusterRoleClusterInformer,
) labelclusterrolebindings.Controller {
	return labelclusterrolebindings.NewController(
		ControllerName,
		tenancy.GroupName,
		replicateclusterrole.HasUseRule,
		func(clusterName logicalcluster.Name, crb *rbacv1.ClusterRoleBinding) bool { return false },
		kubeClusterClient,
		clusterRoleBindingInformer,
		clusterRoleInformer,
	)
}
