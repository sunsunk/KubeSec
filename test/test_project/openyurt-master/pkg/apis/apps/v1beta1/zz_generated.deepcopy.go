//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2023 The OpenYurt Authors.

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

// Code generated by controller-gen. DO NOT EDIT.

package v1beta1

import (
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ContainerImage) DeepCopyInto(out *ContainerImage) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ContainerImage.
func (in *ContainerImage) DeepCopy() *ContainerImage {
	if in == nil {
		return nil
	}
	out := new(ContainerImage)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentTemplateSpec) DeepCopyInto(out *DeploymentTemplateSpec) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentTemplateSpec.
func (in *DeploymentTemplateSpec) DeepCopy() *DeploymentTemplateSpec {
	if in == nil {
		return nil
	}
	out := new(DeploymentTemplateSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePool) DeepCopyInto(out *NodePool) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePool.
func (in *NodePool) DeepCopy() *NodePool {
	if in == nil {
		return nil
	}
	out := new(NodePool)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NodePool) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolList) DeepCopyInto(out *NodePoolList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NodePool, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolList.
func (in *NodePoolList) DeepCopy() *NodePoolList {
	if in == nil {
		return nil
	}
	out := new(NodePoolList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NodePoolList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolSpec) DeepCopyInto(out *NodePoolSpec) {
	*out = *in
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Taints != nil {
		in, out := &in.Taints, &out.Taints
		*out = make([]v1.Taint, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolSpec.
func (in *NodePoolSpec) DeepCopy() *NodePoolSpec {
	if in == nil {
		return nil
	}
	out := new(NodePoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolStatus) DeepCopyInto(out *NodePoolStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolStatus.
func (in *NodePoolStatus) DeepCopy() *NodePoolStatus {
	if in == nil {
		return nil
	}
	out := new(NodePoolStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Patch) DeepCopyInto(out *Patch) {
	*out = *in
	in.Value.DeepCopyInto(&out.Value)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Patch.
func (in *Patch) DeepCopy() *Patch {
	if in == nil {
		return nil
	}
	out := new(Patch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StatefulSetTemplateSpec) DeepCopyInto(out *StatefulSetTemplateSpec) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StatefulSetTemplateSpec.
func (in *StatefulSetTemplateSpec) DeepCopy() *StatefulSetTemplateSpec {
	if in == nil {
		return nil
	}
	out := new(StatefulSetTemplateSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Tweaks) DeepCopyInto(out *Tweaks) {
	*out = *in
	if in.Replicas != nil {
		in, out := &in.Replicas, &out.Replicas
		*out = new(int32)
		**out = **in
	}
	if in.ContainerImages != nil {
		in, out := &in.ContainerImages, &out.ContainerImages
		*out = make([]ContainerImage, len(*in))
		copy(*out, *in)
	}
	if in.Patches != nil {
		in, out := &in.Patches, &out.Patches
		*out = make([]Patch, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Tweaks.
func (in *Tweaks) DeepCopy() *Tweaks {
	if in == nil {
		return nil
	}
	out := new(Tweaks)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Workload) DeepCopyInto(out *Workload) {
	*out = *in
	in.WorkloadTemplate.DeepCopyInto(&out.WorkloadTemplate)
	if in.WorkloadTweaks != nil {
		in, out := &in.WorkloadTweaks, &out.WorkloadTweaks
		*out = make([]WorkloadTweak, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Workload.
func (in *Workload) DeepCopy() *Workload {
	if in == nil {
		return nil
	}
	out := new(Workload)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkloadTemplate) DeepCopyInto(out *WorkloadTemplate) {
	*out = *in
	if in.StatefulSetTemplate != nil {
		in, out := &in.StatefulSetTemplate, &out.StatefulSetTemplate
		*out = new(StatefulSetTemplateSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.DeploymentTemplate != nil {
		in, out := &in.DeploymentTemplate, &out.DeploymentTemplate
		*out = new(DeploymentTemplateSpec)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkloadTemplate.
func (in *WorkloadTemplate) DeepCopy() *WorkloadTemplate {
	if in == nil {
		return nil
	}
	out := new(WorkloadTemplate)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkloadTweak) DeepCopyInto(out *WorkloadTweak) {
	*out = *in
	if in.NodePoolSelector != nil {
		in, out := &in.NodePoolSelector, &out.NodePoolSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Pools != nil {
		in, out := &in.Pools, &out.Pools
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	in.Tweaks.DeepCopyInto(&out.Tweaks)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkloadTweak.
func (in *WorkloadTweak) DeepCopy() *WorkloadTweak {
	if in == nil {
		return nil
	}
	out := new(WorkloadTweak)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *YurtAppSet) DeepCopyInto(out *YurtAppSet) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new YurtAppSet.
func (in *YurtAppSet) DeepCopy() *YurtAppSet {
	if in == nil {
		return nil
	}
	out := new(YurtAppSet)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *YurtAppSet) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *YurtAppSetCondition) DeepCopyInto(out *YurtAppSetCondition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new YurtAppSetCondition.
func (in *YurtAppSetCondition) DeepCopy() *YurtAppSetCondition {
	if in == nil {
		return nil
	}
	out := new(YurtAppSetCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *YurtAppSetList) DeepCopyInto(out *YurtAppSetList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]YurtAppSet, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new YurtAppSetList.
func (in *YurtAppSetList) DeepCopy() *YurtAppSetList {
	if in == nil {
		return nil
	}
	out := new(YurtAppSetList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *YurtAppSetList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *YurtAppSetSpec) DeepCopyInto(out *YurtAppSetSpec) {
	*out = *in
	in.Workload.DeepCopyInto(&out.Workload)
	if in.NodePoolSelector != nil {
		in, out := &in.NodePoolSelector, &out.NodePoolSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Pools != nil {
		in, out := &in.Pools, &out.Pools
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.RevisionHistoryLimit != nil {
		in, out := &in.RevisionHistoryLimit, &out.RevisionHistoryLimit
		*out = new(int32)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new YurtAppSetSpec.
func (in *YurtAppSetSpec) DeepCopy() *YurtAppSetSpec {
	if in == nil {
		return nil
	}
	out := new(YurtAppSetSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *YurtAppSetStatus) DeepCopyInto(out *YurtAppSetStatus) {
	*out = *in
	if in.CollisionCount != nil {
		in, out := &in.CollisionCount, &out.CollisionCount
		*out = new(int32)
		**out = **in
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]YurtAppSetCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new YurtAppSetStatus.
func (in *YurtAppSetStatus) DeepCopy() *YurtAppSetStatus {
	if in == nil {
		return nil
	}
	out := new(YurtAppSetStatus)
	in.DeepCopyInto(out)
	return out
}
