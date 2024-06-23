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

package controllers

import (
	"go.uber.org/fx"

	"github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl"
	"github.com/chaos-mesh/chaos-mesh/controllers/common"
	"github.com/chaos-mesh/chaos-mesh/controllers/multicluster/clusterregistry"
	"github.com/chaos-mesh/chaos-mesh/controllers/multicluster/remotechaos"
	"github.com/chaos-mesh/chaos-mesh/controllers/multicluster/remotecluster"
	"github.com/chaos-mesh/chaos-mesh/controllers/podhttpchaos"
	"github.com/chaos-mesh/chaos-mesh/controllers/podiochaos"
	"github.com/chaos-mesh/chaos-mesh/controllers/podnetworkchaos"
	"github.com/chaos-mesh/chaos-mesh/controllers/schedule"
	"github.com/chaos-mesh/chaos-mesh/controllers/statuscheck"
	"github.com/chaos-mesh/chaos-mesh/controllers/utils/chaosdaemon"
	"github.com/chaos-mesh/chaos-mesh/controllers/utils/recorder"
	wfcontrollers "github.com/chaos-mesh/chaos-mesh/pkg/workflow/controllers"
)

var Module = fx.Options(
	fx.Provide(
		chaosdaemon.New,
		recorder.NewRecorderBuilder,
		common.AllSteps,
		clusterregistry.New,
	),
	fx.Invoke(common.Bootstrap),
	fx.Invoke(podhttpchaos.Bootstrap),
	fx.Invoke(podnetworkchaos.Bootstrap),
	fx.Invoke(podiochaos.Bootstrap),
	fx.Invoke(wfcontrollers.BootstrapWorkflowControllers),
	fx.Invoke(statuscheck.Bootstrap),
	fx.Invoke(remotecluster.Bootstrap),
	fx.Invoke(remotechaos.Bootstrap),

	schedule.Module,
	chaosimpl.AllImpl,
)
