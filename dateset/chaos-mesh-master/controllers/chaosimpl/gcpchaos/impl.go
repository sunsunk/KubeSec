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

package gcpchaos

import (
	"go.uber.org/fx"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
	"github.com/chaos-mesh/chaos-mesh/controllers/action"
	"github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/gcpchaos/diskloss"
	"github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/gcpchaos/nodereset"
	"github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/gcpchaos/nodestop"
	impltypes "github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/types"
)

type Impl struct {
	fx.In

	DiskLoss  *diskloss.Impl  `action:"disk-loss"`
	NodeReset *nodereset.Impl `action:"node-reset"`
	NodeStop  *nodestop.Impl  `action:"node-stop"`
}

func NewImpl(impl Impl) *impltypes.ChaosImplPair {
	delegate := action.NewMultiplexer(&impl)
	return &impltypes.ChaosImplPair{
		Name:   "gcpchaos",
		Object: &v1alpha1.GCPChaos{},
		Impl:   &delegate,
	}
}

var Module = fx.Provide(
	fx.Annotated{
		Group:  "impl",
		Target: NewImpl,
	},
	diskloss.NewImpl,
	nodereset.NewImpl,
	nodestop.NewImpl)
