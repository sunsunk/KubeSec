/*
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

//nolint:dupl
package v1

import (
	"fmt"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var admissionpolicylog = logf.Log.WithName("admissionpolicy-resource")

func (r *AdmissionPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}
	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-admissionpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=admissionpolicies,verbs=create;update,versions=v1,name=madmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &AdmissionPolicy{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *AdmissionPolicy) Default() {
	admissionpolicylog.Info("default", "name", r.Name)
	if r.Spec.PolicyServer == "" {
		r.Spec.PolicyServer = constants.DefaultPolicyServer
	}
	if r.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(r, constants.KubewardenFinalizer)
	}
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-admissionpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=admissionpolicies,verbs=create;update,versions=v1,name=vadmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &AdmissionPolicy{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *AdmissionPolicy) ValidateCreate() (admission.Warnings, error) {
	admissionpolicylog.Info("validate create", "name", r.Name)
	return nil, validateRulesField(r)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *AdmissionPolicy) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	admissionpolicylog.Info("validate update", "name", r.Name)

	oldPolicy, ok := old.(*AdmissionPolicy)
	if !ok {
		return admission.Warnings{}, apierrors.NewInternalError(
			fmt.Errorf("object is not of type AdmissionPolicy: %#v", old))
	}
	return nil, validatePolicyUpdate(oldPolicy, r)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *AdmissionPolicy) ValidateDelete() (admission.Warnings, error) {
	admissionpolicylog.Info("validate delete", "name", r.Name)
	return nil, nil
}
