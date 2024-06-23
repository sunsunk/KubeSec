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

package timechaos

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"go.uber.org/fx"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
	impltypes "github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/types"
	"github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/utils"
	"github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/pb"
	timeUtils "github.com/chaos-mesh/chaos-mesh/pkg/time/utils"
)

var _ impltypes.ChaosImpl = (*Impl)(nil)

type Impl struct {
	client.Client
	Log     logr.Logger
	decoder *utils.ContainerRecordDecoder
}

func (impl *Impl) Apply(ctx context.Context, index int, records []*v1alpha1.Record, obj v1alpha1.InnerObject) (v1alpha1.Phase, error) {
	decodedContainer, err := impl.decoder.DecodeContainerRecord(ctx, records[index], obj)
	pbClient := decodedContainer.PbClient
	containerId := decodedContainer.ContainerId
	if pbClient != nil {
		defer pbClient.Close()
	}
	if err != nil {
		return v1alpha1.NotInjected, err
	}

	timechaos := obj.(*v1alpha1.TimeChaos)
	mask, err := timeUtils.EncodeClkIds(timechaos.Spec.ClockIds)
	if err != nil {
		return v1alpha1.NotInjected, err
	}

	duration, err := time.ParseDuration(timechaos.Spec.TimeOffset)
	if err != nil {
		return v1alpha1.NotInjected, err
	}

	sec, nsec := secAndNSecFromDuration(duration)

	impl.Log.Info("setting time shift", "mask", mask, "sec", sec, "nsec", nsec, "containerId", containerId)
	_, err = pbClient.SetTimeOffset(ctx, &pb.TimeRequest{
		ContainerId:      containerId,
		Sec:              sec,
		Nsec:             nsec,
		ClkIdsMask:       mask,
		Uid:              string(obj.GetUID()) + string(decodedContainer.Pod.GetUID()),
		PodContainerName: fmt.Sprintf("%s:%s", decodedContainer.Pod.GetUID(), decodedContainer.ContainerName),
	})
	if err != nil {
		return v1alpha1.NotInjected, err
	}

	return v1alpha1.Injected, nil
}

func (impl *Impl) Recover(ctx context.Context, index int, records []*v1alpha1.Record, obj v1alpha1.InnerObject) (v1alpha1.Phase, error) {
	decodedContainer, err := impl.decoder.DecodeContainerRecord(ctx, records[index], obj)
	pbClient := decodedContainer.PbClient
	containerId := decodedContainer.ContainerId
	if pbClient != nil {
		defer pbClient.Close()
	}
	if err != nil {
		if errors.Is(err, utils.ErrContainerNotFound) {
			// pretend the disappeared container has been recovered
			return v1alpha1.NotInjected, nil
		}
		return v1alpha1.Injected, err
	}

	impl.Log.Info("recover for container", "containerId", containerId)
	_, err = pbClient.RecoverTimeOffset(ctx, &pb.TimeRequest{
		ContainerId:      containerId,
		Uid:              string(obj.GetUID()) + string(decodedContainer.Pod.GetUID()),
		PodContainerName: fmt.Sprintf("%s:%s", decodedContainer.Pod.GetUID(), decodedContainer.ContainerName),
	})
	if err != nil {
		return v1alpha1.Injected, err
	}

	return v1alpha1.NotInjected, nil
}

func secAndNSecFromDuration(duration time.Duration) (sec int64, nsec int64) {
	sec = duration.Nanoseconds() / 1e9
	nsec = duration.Nanoseconds() - (sec * 1e9)

	return
}

func NewImpl(c client.Client, log logr.Logger, decoder *utils.ContainerRecordDecoder) *impltypes.ChaosImplPair {
	return &impltypes.ChaosImplPair{
		Name:   "timechaos",
		Object: &v1alpha1.TimeChaos{},
		Impl: &Impl{
			Client:  c,
			Log:     log.WithName("timechaos"),
			decoder: decoder,
		},
	}
}

var Module = fx.Provide(
	fx.Annotated{
		Group:  "impl",
		Target: NewImpl,
	},
)
