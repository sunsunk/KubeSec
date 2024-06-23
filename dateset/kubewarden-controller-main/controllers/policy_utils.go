/*
Copyright 2022.

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

package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/metrics"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/naming"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func setPolicyStatus(ctx context.Context, deploymentsNamespace string, apiReader client.Reader, policy policiesv1.Policy) error {
	policyServerDeployment := appsv1.Deployment{}
	if err := apiReader.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: naming.PolicyServerDeploymentNameForPolicyServerName(policy.GetPolicyServer())}, &policyServerDeployment); err != nil {
		return errors.Join(errors.New("could not get policy server deployment"), err)
	}

	policyServerConfigMap := corev1.ConfigMap{}
	if err := apiReader.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: naming.PolicyServerDeploymentNameForPolicyServerName(policy.GetPolicyServer())}, &policyServerConfigMap); err != nil {
		return errors.Join(errors.New("could not get configmap"), err)
	}

	policyMap, err := getPolicyMapFromConfigMap(&policyServerConfigMap)
	if err == nil {
		if policyConfig, ok := policyMap[policy.GetUniqueName()]; ok {
			policy.SetPolicyModeStatus(policiesv1.PolicyModeStatus(policyConfig.PolicyMode))
		} else {
			policy.SetPolicyModeStatus(policiesv1.PolicyModeStatusUnknown)
		}
	} else {
		policy.SetPolicyModeStatus(policiesv1.PolicyModeStatusUnknown)
	}

	policyStatus := policy.GetStatus()
	SetPolicyConfigurationCondition(&policyServerConfigMap, &policyServerDeployment, &policyStatus.Conditions)

	return nil
}

func startReconciling(ctx context.Context, client client.Client, reconciler admission.Reconciler, policy policiesv1.Policy) (ctrl.Result, error) {
	if policy.GetDeletionTimestamp() != nil {
		return reconcilePolicyDeletion(ctx, client, policy)
	}

	reconcileResult, reconcileErr := reconcilePolicy(ctx, client, reconciler, policy)

	_ = setPolicyStatus(ctx, reconciler.DeploymentsNamespace, reconciler.APIReader, policy)
	if err := client.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("update admission policy status error: %w", err)
	}

	// record policy count metric
	if err := metrics.RecordPolicyCount(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to record policy mestrics: %w", err)
	}

	return reconcileResult, reconcileErr
}

func reconcilePolicy(ctx context.Context, client client.Client, reconciler admission.Reconciler, policy policiesv1.Policy) (ctrl.Result, error) {
	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyActive),
			Status:  metav1.ConditionFalse,
			Reason:  "PolicyActive",
			Message: "The policy webhook has not been created",
		},
	)
	if policy.GetPolicyServer() == "" {
		policy.SetStatus(policiesv1.PolicyStatusUnscheduled)
		return ctrl.Result{}, nil
	}

	policyServer, err := getPolicyServer(ctx, client, policy)
	if err != nil {
		policy.SetStatus(policiesv1.PolicyStatusScheduled)
		//lint:ignore nilerr set status to scheduled if policyServer can't be retrieved, and stop reconciling
		return ctrl.Result{}, nil
	}
	if policy.GetStatus().PolicyStatus != policiesv1.PolicyStatusActive {
		policy.SetStatus(policiesv1.PolicyStatusPending)
	}

	policyServerDeployment := appsv1.Deployment{}
	if err := reconciler.APIReader.Get(ctx, types.NamespacedName{Namespace: reconciler.DeploymentsNamespace, Name: naming.PolicyServerDeploymentNameForPolicyServerName(policy.GetPolicyServer())}, &policyServerDeployment); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, errors.Join(errors.New("could not read policy server Deployment"), err)
	}

	if !isPolicyUniquelyReachable(ctx, client, &policyServerDeployment, policy.GetUniqueName()) {
		apimeta.SetStatusCondition(
			&policy.GetStatus().Conditions,
			metav1.Condition{
				Type:    string(policiesv1.PolicyUniquelyReachable),
				Status:  metav1.ConditionFalse,
				Reason:  "LatestReplicaSetIsNotUniquelyReachable",
				Message: "The latest replica set is not uniquely reachable",
			},
		)
		return ctrl.Result{Requeue: true, RequeueAfter: 2 * time.Second}, nil
	}

	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyUniquelyReachable),
			Status:  metav1.ConditionTrue,
			Reason:  "LatestReplicaSetIsUniquelyReachable",
			Message: "The latest replica set is uniquely reachable",
		},
	)

	secret := corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: reconciler.DeploymentsNamespace, Name: constants.PolicyServerCARootSecretName}, &secret); err != nil {
		return ctrl.Result{}, errors.Join(errors.New("cannot find policy server secret"), err)
	}

	if policy.IsMutating() {
		if err := reconciler.ReconcileMutatingWebhookConfiguration(ctx, policy, &secret, policyServer.NameWithPrefix()); err != nil {
			return ctrl.Result{}, errors.Join(errors.New("error reconciling mutating webhook"), err)
		}
	} else {
		if err := reconciler.ReconcileValidatingWebhookConfiguration(ctx, policy, &secret, policyServer.NameWithPrefix()); err != nil {
			return ctrl.Result{}, errors.Join(errors.New("error reconciling validating webhook"), err)
		}
	}
	setPolicyAsActive(policy)

	return ctrl.Result{}, nil
}

func setPolicyAsActive(policy policiesv1.Policy) {
	policy.SetStatus(policiesv1.PolicyStatusActive)
	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyActive),
			Status:  metav1.ConditionTrue,
			Reason:  "PolicyActive",
			Message: "The policy webhook has been created",
		},
	)
}

func getPolicyServer(ctx context.Context, client client.Client, policy policiesv1.Policy) (*policiesv1.PolicyServer, error) {
	policyServer := policiesv1.PolicyServer{}
	if err := client.Get(ctx, types.NamespacedName{Name: policy.GetPolicyServer()}, &policyServer); err != nil {
		return nil, errors.Join(errors.New("could not get policy server"), err)
	}
	return &policyServer, nil
}

func reconcilePolicyDeletion(ctx context.Context, client client.Client, policy policiesv1.Policy) (ctrl.Result, error) {
	if policy.IsMutating() {
		if err := reconcileMutatingWebhook(ctx, client, policy); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := reconcileValidatingWebhook(ctx, client, policy); err != nil {
			return ctrl.Result{}, err
		}
	}
	controllerutil.RemoveFinalizer(policy, constants.KubewardenFinalizer)
	if err := client.Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("cannot update admission policy: %w", err)
	}
	return ctrl.Result{}, nil
}

func reconcileValidatingWebhook(ctx context.Context, client client.Client, admissionPolicy policiesv1.Policy) error {
	webhook := admissionregistrationv1.ValidatingWebhookConfiguration{}
	err := client.Get(ctx, types.NamespacedName{Name: admissionPolicy.GetUniqueName()}, &webhook)
	if err == nil {
		if err := client.Delete(ctx, &webhook); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("cannot delete validating webhook: %w", err)
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("cannot retrieve validating webhook: %w", err)
	}
	return nil
}

func reconcileMutatingWebhook(ctx context.Context, client client.Client, admissionPolicy policiesv1.Policy) error {
	webhook := admissionregistrationv1.MutatingWebhookConfiguration{}
	err := client.Get(ctx, types.NamespacedName{Name: admissionPolicy.GetUniqueName()}, &webhook)
	if err == nil {
		if err := client.Delete(ctx, &webhook); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("cannot delete mutating webhook: %w", err)
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("cannot retrieve mutating webhook: %w", err)
	}
	return nil
}
