/*
Copyright 2023 The Volcano Authors.

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

package gpushare

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestGetGPUMemoryOfPod(t *testing.T) {
	testCases := []struct {
		name string
		pod  *v1.Pod
		want uint
	}{
		{
			name: "GPUs required only in Containers",
			pod: &v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUResource: resource.MustParse("1"),
								},
							},
						},
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUResource: resource.MustParse("3"),
								},
							},
						},
					},
				},
			},
			want: 4,
		},
		{
			name: "GPUs required both in initContainers and Containers",
			pod: &v1.Pod{
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUResource: resource.MustParse("1"),
								},
							},
						},
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUResource: resource.MustParse("3"),
								},
							},
						},
					},
					Containers: []v1.Container{
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUResource: resource.MustParse("2"),
								},
							},
						},
					},
				},
			},
			want: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getGPUMemoryOfPod(tc.pod)
			if tc.want != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.want, got)
			}
		})
	}
}

func TestGetGPUNumberOfPod(t *testing.T) {
	testCases := []struct {
		name string
		pod  *v1.Pod
		want int
	}{
		{
			name: "GPUs required only in Containers",
			pod: &v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUNumber: resource.MustParse("1"),
								},
							},
						},
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUNumber: resource.MustParse("3"),
								},
							},
						},
					},
				},
			},
			want: 4,
		},
		{
			name: "GPUs required both in initContainers and Containers",
			pod: &v1.Pod{
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUNumber: resource.MustParse("1"),
								},
							},
						},
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUNumber: resource.MustParse("3"),
								},
							},
						},
					},
					Containers: []v1.Container{
						{
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									VolcanoGPUNumber: resource.MustParse("2"),
								},
							},
						},
					},
				},
			},
			want: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getGPUNumberOfPod(tc.pod)
			if tc.want != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.want, got)
			}
		})
	}
}
