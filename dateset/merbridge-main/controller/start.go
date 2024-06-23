/*
Copyright © 2022 Merbridge Authors

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

package controller

import (
	"fmt"

	"k8s.io/client-go/kubernetes"

	"github.com/merbridge/merbridge/app/cmd/options"
	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/internal/process"
	"github.com/merbridge/merbridge/pkg/kube"
)

// Run start to run controller to watch
func Run(cniReady chan struct{}, pm process.ProcessManager, stop chan struct{}) error {
	var err error
	var client kubernetes.Interface

	// create and check start up configuration
	err = options.NewOptions()
	if err != nil {
		return fmt.Errorf("create options error: %v", err)
	}

	// get default kubernetes client
	client, err = kube.GetKubernetesClientWithFile(config.KubeConfig, config.Context)
	if err != nil {
		return fmt.Errorf("create client error: %v", err)
	}

	// run local ip controller
	if err = RunLocalPodController(client, pm, stop); err != nil {
		return fmt.Errorf("run local ip controller error: %v", err)
	}

	return nil
}
