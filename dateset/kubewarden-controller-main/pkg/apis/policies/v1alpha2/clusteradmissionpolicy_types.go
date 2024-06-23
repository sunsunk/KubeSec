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

package v1alpha2

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy
type ClusterAdmissionPolicySpec struct {
	PolicySpec `json:""` //nolint

	// NamespaceSelector decides whether to run the webhook on an object based
	// on whether the namespace for that object matches the selector. If the
	// object itself is a namespace, the matching is performed on
	// object.metadata.labels. If the object is another cluster scoped resource,
	// it never skips the webhook.
	// <br/><br/>
	// For example, to run the webhook on any objects whose namespace is not
	// associated with "runlevel" of "0" or "1";  you will set the selector as
	// follows:
	// <pre>
	// "namespaceSelector": \{<br/>
	// &nbsp;&nbsp;"matchExpressions": [<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;\{<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "runlevel",<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "NotIn",<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"0",<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"1"<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;\}<br/>
	// &nbsp;&nbsp;]<br/>
	// \}
	// </pre>
	// If instead you want to only run the webhook on any objects whose
	// namespace is associated with the "environment" of "prod" or "staging";
	// you will set the selector as follows:
	// <pre>
	// "namespaceSelector": \{<br/>
	// &nbsp;&nbsp;"matchExpressions": [<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;\{<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "environment",<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "In",<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"prod",<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"staging"<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/>
	// &nbsp;&nbsp;&nbsp;&nbsp;\}<br/>
	// &nbsp;&nbsp;]<br/>
	// \}
	// </pre>
	// See
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
	// for more examples of label selectors.
	// <br/><br/>
	// Default to the empty LabelSelector, which matches everything.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Policy Server",type=string,JSONPath=`.spec.policyServer`,description="Bound to Policy Server"
// +kubebuilder:printcolumn:name="Mutating",type=boolean,JSONPath=`.spec.mutating`,description="Whether the policy is mutating"
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`,description="Policy deployment mode"
// +kubebuilder:printcolumn:name="Observed mode",type=string,JSONPath=`.status.mode`,description="Policy deployment mode observed on the assigned Policy Server"
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.policyStatus`,description="Status of the policy"
type ClusterAdmissionPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterAdmissionPolicySpec `json:"spec,omitempty"`
	Status PolicyStatus               `json:"status,omitempty"`
}

// ClusterAdmissionPolicyList contains a list of ClusterAdmissionPolicy
// +kubebuilder:object:root=true
type ClusterAdmissionPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterAdmissionPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterAdmissionPolicy{}, &ClusterAdmissionPolicyList{})
}

func (r *ClusterAdmissionPolicy) SetStatus(status PolicyStatusEnum) {
	r.Status.PolicyStatus = status
}

func (r *ClusterAdmissionPolicy) GetPolicyMode() PolicyMode {
	return r.Spec.Mode
}

func (r *ClusterAdmissionPolicy) SetPolicyModeStatus(policyMode PolicyModeStatus) {
	r.Status.PolicyMode = policyMode
}

func (r *ClusterAdmissionPolicy) GetModule() string {
	return r.Spec.Module
}

func (r *ClusterAdmissionPolicy) IsMutating() bool {
	return r.Spec.Mutating
}

func (r *ClusterAdmissionPolicy) GetSettings() runtime.RawExtension {
	return r.Spec.Settings
}

func (r *ClusterAdmissionPolicy) GetStatus() *PolicyStatus {
	return &r.Status
}

func (r *ClusterAdmissionPolicy) CopyInto(policy *Policy) {
	*policy = r.DeepCopy()
}

func (r *ClusterAdmissionPolicy) GetSideEffects() *admissionregistrationv1.SideEffectClass {
	return r.Spec.SideEffects
}

func (r *ClusterAdmissionPolicy) GetFailurePolicy() *admissionregistrationv1.FailurePolicyType {
	return r.Spec.FailurePolicy
}

func (r *ClusterAdmissionPolicy) GetMatchPolicy() *admissionregistrationv1.MatchPolicyType {
	return r.Spec.MatchPolicy
}

func (r *ClusterAdmissionPolicy) GetRules() []admissionregistrationv1.RuleWithOperations {
	return r.Spec.Rules
}

func (r *ClusterAdmissionPolicy) GetNamespaceSelector() *metav1.LabelSelector {
	return r.Spec.NamespaceSelector
}

func (r *ClusterAdmissionPolicy) GetObjectSelector() *metav1.LabelSelector {
	return r.Spec.ObjectSelector
}

func (r *ClusterAdmissionPolicy) GetTimeoutSeconds() *int32 {
	return r.Spec.TimeoutSeconds
}

func (r *ClusterAdmissionPolicy) GetObjectMeta() *metav1.ObjectMeta {
	return &r.ObjectMeta
}

func (r *ClusterAdmissionPolicy) GetPolicyServer() string {
	return r.Spec.PolicyServer
}

func (r *ClusterAdmissionPolicy) GetUniqueName() string {
	return "clusterwide-" + r.Name
}
