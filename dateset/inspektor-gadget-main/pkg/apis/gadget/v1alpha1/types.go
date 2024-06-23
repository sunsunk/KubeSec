// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// Operation defines the gadget operation applied to the trace
type Operation string

const (
	// OperationStart indicates to start the trace
	OperationStart Operation = "start"
	// OperationStop indicates to stop the trace
	OperationStop Operation = "stop"
	// OperationGenerate indicates to generate the trace
	// output e.g seccomp profile
	OperationGenerate Operation = "generate"
	// OperationCollect indicates capturing system state
	// at a specific point in time
	OperationCollect Operation = "collect"
	// OperationDelete indicates we want to delete a resource which is owned by a
	// trace. At the moment, this is only used by traceloop.
	OperationDelete Operation = "delete"
)

// RunMode defines running mode for the Trace
// +kubebuilder:validation:Enum=Auto;Manual
type RunMode string

const (
	// RunModeAuto automatically starts the trace as soon
	// as the resource is created.
	RunModeAuto RunMode = "Auto"
	// RunModeManual allows the trace to be controlled by the
	// "gadget.kinvolk.io/operation" annotation.
	RunModeManual RunMode = "Manual"
)

// TraceOutputMode defines output mode for the Trace
// +kubebuilder:validation:Enum=Status;Stream;File;ExternalResource
type TraceOutputMode string

const (
	// TraceOutputModeStatus indicates to store the output in the trace "Status.Output" field
	TraceOutputModeStatus TraceOutputMode = "Status"
	// TraceOutputModeStream indicates to stream events. This stream can be accessed through the Stream() api on the gadget tracer manager
	TraceOutputModeStream TraceOutputMode = "Stream"
	// TraceOutputModeFile indicates to save output into a file
	TraceOutputModeFile TraceOutputMode = "File"
	// TraceOutputModeExternalResource indicates to create an external resource, as a seccomp profile
	TraceOutputModeExternalResource TraceOutputMode = "ExternalResource"
)

// ContainerFilter filters events based on different criteria
type ContainerFilter struct {
	// Namespace selects events from this pod namespace
	Namespace string `json:"namespace,omitempty"`

	// Podname selects events from this pod name
	Podname string `json:"podname,omitempty"`

	// Labels selects events from pods with these labels
	Labels map[string]string `json:"labels,omitempty"`

	// ContainerName selects events from containers with this name
	ContainerName string `json:"containerName,omitempty"`
}

// TraceSpec defines the desired state of Trace
type TraceSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Node is the name of the node on which this trace should run
	Node string `json:"node,omitempty"`

	// Gadget is the name of the gadget such as "seccomp"
	Gadget string `json:"gadget,omitempty"`

	// RunMode is "Auto" to automatically start the trace as soon as the
	// resource is created, or "Manual" to be controlled by the
	// "gadget.kinvolk.io/operation" annotation
	RunMode RunMode `json:"runMode,omitempty"`

	// Filter is to tell the gadget to filter events based on namespace,
	// pod name, labels or container name
	Filter *ContainerFilter `json:"filter,omitempty"`

	// OutputMode is "Status", "Stream", "File" or "ExternalResource"
	OutputMode TraceOutputMode `json:"outputMode,omitempty"`

	// Output allows a gadget to output the results in the specified
	// location.
	// * With OutputMode=Status|Stream, Output is unused
	// * With OutputMode=File, Output specifies the file path
	// * With OutputMode=ExternalResource, Output specifies the external
	//   resource (such as
	//   seccompprofiles.security-profiles-operator.x-k8s.io for the
	//   seccomp gadget)
	Output string `json:"output,omitempty"`

	// TODO: Ideally it should be a map[string]interface{} but it's not
	// supported: https://github.com/kubernetes-sigs/controller-tools/issues/636

	// Parameters contains gadget specific configurations.
	Parameters map[string]string `json:"parameters,omitempty"`
}

// TraceState defines state for the trace
// +kubebuilder:validation:Enum=Started;Stopped;Completed
type TraceState string

const (
	// TraceStateStarted indicates trace is in started state
	TraceStateStarted TraceState = "Started"
	// TraceStateStopped indicates trace is in stopped state
	TraceStateStopped TraceState = "Stopped"
	// TraceStateCompleted indicates trace is in completed state
	TraceStateCompleted TraceState = "Completed"
)

// TraceStatus defines the observed state of Trace
type TraceStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// State is "Started", "Stopped" or "Completed"
	State TraceState `json:"state,omitempty"`

	// Output is the output of the gadget
	Output string `json:"output,omitempty"`

	// OperationError is the error returned by the gadget when applying the
	// annotation gadget.kinvolk.io/operation=
	OperationError string `json:"operationError,omitempty"`

	// OperationWarning is returned by the gadget to notify about a malfunction
	// when applying the annotation gadget.kinvolk.io/operation=. Unlike the
	// OperationError that represents a fatal error, the OperationWarning could
	// be ignored according to the context.
	OperationWarning string `json:"operationWarning,omitempty"`
}

// +genclient
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Trace is the Schema for the traces API
type Trace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TraceSpec   `json:"spec,omitempty"`
	Status TraceStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// TraceList contains a list of Trace
type TraceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Trace `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Trace{}, &TraceList{})
}
