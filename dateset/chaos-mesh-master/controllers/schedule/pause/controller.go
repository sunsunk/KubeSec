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

package pause

import (
	"context"
	"fmt"
	"reflect"
	"strconv"

	"github.com/go-logr/logr"
	k8sError "k8s.io/apimachinery/pkg/api/errors"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
	"github.com/chaos-mesh/chaos-mesh/controllers/config"
	"github.com/chaos-mesh/chaos-mesh/controllers/schedule/utils"
	"github.com/chaos-mesh/chaos-mesh/controllers/utils/builder"
	"github.com/chaos-mesh/chaos-mesh/controllers/utils/recorder"
)

type Reconciler struct {
	client.Client
	Log          logr.Logger
	ActiveLister *utils.ActiveLister

	Recorder recorder.ChaosRecorder
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	schedule := &v1alpha1.Schedule{}
	err := r.Get(ctx, req.NamespacedName, schedule)
	if err != nil {
		if !k8sError.IsNotFound(err) {
			r.Log.Error(err, "unable to get chaos")
		}
		return ctrl.Result{}, nil
	}

	if schedule.Spec.Type == v1alpha1.ScheduleTypeWorkflow {
		if schedule.IsPaused() {
			r.Recorder.Event(schedule, recorder.NotSupported{
				Activity: "pausing a workflow schedule",
			})
		}
		return ctrl.Result{}, nil
	}

	list, err := r.ActiveLister.ListActiveJobs(ctx, schedule)
	if err != nil {
		r.Recorder.Event(schedule, recorder.Failed{
			Activity: "list active jobs",
			Err:      err.Error(),
		})
		return ctrl.Result{}, nil
	}

	items := reflect.ValueOf(list).Elem().FieldByName("Items")
	for i := 0; i < items.Len(); i++ {
		item := items.Index(i).Addr().Interface().(v1alpha1.InnerObject)
		if item.IsPaused() != schedule.IsPaused() {
			key := k8sTypes.NamespacedName{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			pause := strconv.FormatBool(schedule.IsPaused())

			updateError := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				r.Log.Info("updating object", "pause", schedule.IsPaused())

				if err := r.Client.Get(ctx, key, item); err != nil {
					r.Log.Error(err, "unable to get schedule")
					return err
				}
				annotations := item.GetAnnotations()
				if annotations == nil {
					annotations = make(map[string]string)
				}
				annotations[v1alpha1.PauseAnnotationKey] = pause
				item.SetAnnotations(annotations)

				return r.Client.Update(ctx, item)
			})
			if updateError != nil {
				r.Log.Error(updateError, "fail to update")
				r.Recorder.Event(schedule, recorder.Failed{
					Activity: fmt.Sprintf("set pause to %s for %s", pause, key),
					Err:      updateError.Error(),
				})
				return ctrl.Result{}, nil
			}
		}
	}

	return ctrl.Result{}, nil
}

const controllerName = "schedule-pause"

func Bootstrap(mgr ctrl.Manager, client client.Client, log logr.Logger, lister *utils.ActiveLister, recorderBuilder *recorder.RecorderBuilder) error {
	if !config.ShouldSpawnController(controllerName) {
		return nil
	}
	return builder.Default(mgr).
		For(&v1alpha1.Schedule{}).
		Named(controllerName).
		Complete(&Reconciler{
			client,
			log.WithName(controllerName),
			lister,
			recorderBuilder.Build(controllerName),
		})
}
