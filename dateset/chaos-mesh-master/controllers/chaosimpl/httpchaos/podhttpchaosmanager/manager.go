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

package podhttpchaosmanager

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	k8sError "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
)

var (
	// ErrPodNotFound means operate pod may be deleted(almostly)
	ErrPodNotFound = errors.New("pod not found")

	// ErrPodNotRunning means operate pod may be not working
	// and it's non-sense to make changes on it.
	ErrPodNotRunning = errors.New("pod not running")
)

// PodHttpManager will save all the related podhttpchaos
type PodHttpManager struct {
	Source string

	Log logr.Logger
	client.Client
	client.Reader
	scheme *runtime.Scheme

	Key types.NamespacedName
	T   *PodHttpTransaction
}

// CommitResponse is a tuple (Key, Err)
type CommitResponse struct {
	Key types.NamespacedName
	Err error
}

// Commit will update all modifications to the cluster
func (m *PodHttpManager) Commit(ctx context.Context) (int64, error) {
	m.Log.Info("running modification on pod", "key", m.Key, "modification", m.T)
	updateError := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		chaos := &v1alpha1.PodHttpChaos{}

		err := m.Client.Get(ctx, m.Key, chaos)
		if err != nil {
			if !k8sError.IsNotFound(err) {
				m.Log.Error(err, "error while getting podhttpchaos")
				return err
			}

			err := m.CreateNewPodHttpChaos(ctx)
			if err != nil {
				m.Log.Error(err, "error while creating new podhttpchaos")
				return err
			}

			return nil
		}

		err = m.T.Apply(chaos)
		if err != nil {
			m.Log.Error(err, "error while applying transactions", "transaction", m.T)
			return err
		}

		return m.Client.Update(ctx, chaos)
	})

	if updateError != nil {
		return 0, updateError
	}

	chaos := &v1alpha1.PodHttpChaos{}
	err := m.Reader.Get(ctx, m.Key, chaos)
	if err != nil {
		m.Log.Error(err, "error while getting the latest generation number")
		return 0, err
	}
	return chaos.GetGeneration(), nil
}

func (m *PodHttpManager) CreateNewPodHttpChaos(ctx context.Context) error {
	var err error
	chaos := &v1alpha1.PodHttpChaos{}

	pod := v1.Pod{}
	err = m.Client.Get(ctx, m.Key, &pod)
	if err != nil {
		if !k8sError.IsNotFound(err) {
			m.Log.Error(err, "error while finding pod")
			return err
		}

		m.Log.Info("pod not found", "key", m.Key, "error", err.Error())
		err = ErrPodNotFound
		return err
	}

	if pod.Status.Phase != v1.PodRunning {
		m.Log.Info("pod is not running", "key", m.Key)
		err = ErrPodNotRunning
		return err
	}

	chaos.Name = m.Key.Name
	chaos.Namespace = m.Key.Namespace
	chaos.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: pod.APIVersion,
			Kind:       pod.Kind,
			Name:       pod.Name,
			UID:        pod.UID,
		},
	}
	err = m.T.Apply(chaos)
	if err != nil {
		m.Log.Error(err, "error while applying transactions", "transaction", m.T)
		return err
	}

	return m.Client.Create(ctx, chaos)
}
