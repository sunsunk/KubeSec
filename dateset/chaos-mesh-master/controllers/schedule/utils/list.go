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

package utils

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
)

type ActiveLister struct {
	client.Client
	Log logr.Logger
}

// TODO: use another easy-to-used type for describing ChaosList
func (lister *ActiveLister) ListActiveJobs(ctx context.Context, schedule *v1alpha1.Schedule) (v1alpha1.GenericChaosList, error) {
	kind, ok := v1alpha1.AllScheduleItemKinds()[string(schedule.Spec.Type)]
	if !ok {
		lister.Log.Info("unknown kind", "kind", schedule.Spec.Type)
		return nil, errors.Errorf("Unknown type: %s", schedule.Spec.Type)
	}

	list := kind.SpawnList()
	err := lister.List(ctx, list, client.MatchingLabels{v1alpha1.LabelManagedBy: schedule.Name})
	if err != nil {
		lister.Log.Error(err, "fail to list chaos")
		return nil, nil
	}

	return list, nil
}

func NewActiveLister(c client.Client, logger logr.Logger) *ActiveLister {
	return &ActiveLister{
		Client: c,
		Log:    logger.WithName("activeLister"),
	}
}
