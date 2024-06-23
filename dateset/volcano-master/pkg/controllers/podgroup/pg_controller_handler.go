/*
Copyright 2019 The Volcano Authors.

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

package podgroup

import (
	"context"
	"encoding/json"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	batchv1alpha1 "volcano.sh/apis/pkg/apis/batch/v1alpha1"
	"volcano.sh/apis/pkg/apis/helpers"
	scheduling "volcano.sh/apis/pkg/apis/scheduling/v1beta1"
	"volcano.sh/volcano/pkg/controllers/util"
)

type podRequest struct {
	podName      string
	podNamespace string
}

type metadataForMergePatch struct {
	Metadata annotationForMergePatch `json:"metadata"`
}

type annotationForMergePatch struct {
	Annotations map[string]string `json:"annotations"`
}

func (pg *pgcontroller) addPod(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		klog.Errorf("Failed to convert %v to v1.Pod", obj)
		return
	}

	req := podRequest{
		podName:      pod.Name,
		podNamespace: pod.Namespace,
	}

	pg.queue.Add(req)
}

func (pg *pgcontroller) addReplicaSet(obj interface{}) {
	rs, ok := obj.(*appsv1.ReplicaSet)
	if !ok {
		klog.Errorf("Failed to convert %v to appsv1.ReplicaSet", obj)
		return
	}

	if *rs.Spec.Replicas == 0 {
		pgName := batchv1alpha1.PodgroupNamePrefix + string(rs.UID)
		err := pg.vcClient.SchedulingV1beta1().PodGroups(rs.Namespace).Delete(context.TODO(), pgName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			klog.Errorf("Failed to delete PodGroup <%s/%s>: %v", rs.Namespace, pgName, err)
		}
	}
}

func (pg *pgcontroller) updateReplicaSet(oldObj, newObj interface{}) {
	pg.addReplicaSet(newObj)
}

func (pg *pgcontroller) updatePodAnnotations(pod *v1.Pod, pgName string) error {
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	if pod.Annotations[scheduling.KubeGroupNameAnnotationKey] == "" {
		patch := metadataForMergePatch{
			Metadata: annotationForMergePatch{
				Annotations: map[string]string{
					scheduling.KubeGroupNameAnnotationKey: pgName,
				},
			},
		}

		patchBytes, err := json.Marshal(&patch)
		if err != nil {
			klog.Errorf("Failed to json.Marshal pod annotation: %v", err)
			return err
		}

		if _, err := pg.kubeClient.CoreV1().Pods(pod.Namespace).Patch(context.TODO(), pod.Name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
			klog.Errorf("Failed to update pod <%s/%s>: %v", pod.Namespace, pod.Name, err)
			return err
		}
	} else {
		if pod.Annotations[scheduling.KubeGroupNameAnnotationKey] != pgName {
			klog.Errorf("normal pod %s/%s annotations %s value is not %s, but %s", pod.Namespace, pod.Name,
				scheduling.KubeGroupNameAnnotationKey, pgName, pod.Annotations[scheduling.KubeGroupNameAnnotationKey])
		}
	}
	return nil
}

func (pg *pgcontroller) getAnnotationsFromUpperRes(kind string, name string, namespace string) map[string]string {
	switch kind {
	case "ReplicaSet":
		rs, err := pg.kubeClient.AppsV1().ReplicaSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			klog.Errorf("Failed to get upper %s for Pod <%s/%s>: %v", kind, namespace, name, err)
			return map[string]string{}
		}
		return rs.Annotations
	case "DaemonSet":
		ds, err := pg.kubeClient.AppsV1().DaemonSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			klog.Errorf("Failed to get upper %s for Pod <%s/%s>: %v", kind, namespace, name, err)
			return map[string]string{}
		}
		return ds.Annotations
	case "StatefulSet":
		ss, err := pg.kubeClient.AppsV1().StatefulSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			klog.Errorf("Failed to get upper %s for Pod <%s/%s>: %v", kind, namespace, name, err)
			return map[string]string{}
		}
		return ss.Annotations
	case "Job":
		job, err := pg.kubeClient.BatchV1().Jobs(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			klog.Errorf("Failed to get upper %s for Pod <%s/%s>: %v", kind, namespace, name, err)
			return map[string]string{}
		}
		return job.Annotations
	default:
		return map[string]string{}
	}
}

// Inherit annotations from upper resources.
func (pg *pgcontroller) inheritUpperAnnotations(pod *v1.Pod, obj *scheduling.PodGroup) {
	if pg.inheritOwnerAnnotations {
		for _, reference := range pod.OwnerReferences {
			if reference.Kind != "" && reference.Name != "" {
				var upperAnnotations = pg.getAnnotationsFromUpperRes(reference.Kind, reference.Name, pod.Namespace)
				for k, v := range upperAnnotations {
					if strings.HasPrefix(k, scheduling.AnnotationPrefix) {
						obj.Annotations[k] = v
					}
				}
			}
		}
	}
}

func (pg *pgcontroller) createNormalPodPGIfNotExist(pod *v1.Pod) error {
	pgName := helpers.GeneratePodgroupName(pod)

	if _, err := pg.pgLister.PodGroups(pod.Namespace).Get(pgName); err != nil {
		if !apierrors.IsNotFound(err) {
			klog.Errorf("Failed to get normal PodGroup for Pod <%s/%s>: %v",
				pod.Namespace, pod.Name, err)
			return err
		}

		obj := &scheduling.PodGroup{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       pod.Namespace,
				Name:            pgName,
				OwnerReferences: newPGOwnerReferences(pod),
				Annotations:     map[string]string{},
				Labels:          map[string]string{},
			},
			Spec: scheduling.PodGroupSpec{
				MinMember:         1,
				PriorityClassName: pod.Spec.PriorityClassName,
				MinResources:      util.GetPodQuotaUsage(pod),
			},
			Status: scheduling.PodGroupStatus{
				Phase: scheduling.PodGroupPending,
			},
		}

		pg.inheritUpperAnnotations(pod, obj)
		// Individual annotations on pods would overwrite annotations inherited from upper resources.
		if queueName, ok := pod.Annotations[scheduling.QueueNameAnnotationKey]; ok {
			obj.Spec.Queue = queueName
		}

		if value, ok := pod.Annotations[scheduling.PodPreemptable]; ok {
			obj.Annotations[scheduling.PodPreemptable] = value
		}
		if value, ok := pod.Annotations[scheduling.CooldownTime]; ok {
			obj.Annotations[scheduling.CooldownTime] = value
		}
		if value, ok := pod.Annotations[scheduling.RevocableZone]; ok {
			obj.Annotations[scheduling.RevocableZone] = value
		}
		if value, ok := pod.Labels[scheduling.PodPreemptable]; ok {
			obj.Labels[scheduling.PodPreemptable] = value
		}
		if value, ok := pod.Labels[scheduling.CooldownTime]; ok {
			obj.Labels[scheduling.CooldownTime] = value
		}

		if value, found := pod.Annotations[scheduling.JDBMinAvailable]; found {
			obj.Annotations[scheduling.JDBMinAvailable] = value
		} else if value, found := pod.Annotations[scheduling.JDBMaxUnavailable]; found {
			obj.Annotations[scheduling.JDBMaxUnavailable] = value
		}

		if _, err := pg.vcClient.SchedulingV1beta1().PodGroups(pod.Namespace).Create(context.TODO(), obj, metav1.CreateOptions{}); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				klog.Errorf("Failed to create normal PodGroup for Pod <%s/%s>: %v",
					pod.Namespace, pod.Name, err)
				return err
			}
		}
	}

	return pg.updatePodAnnotations(pod, pgName)
}

func newPGOwnerReferences(pod *v1.Pod) []metav1.OwnerReference {
	if len(pod.OwnerReferences) != 0 {
		for _, ownerReference := range pod.OwnerReferences {
			if ownerReference.Controller != nil && *ownerReference.Controller {
				return pod.OwnerReferences
			}
		}
	}

	gvk := schema.GroupVersionKind{
		Group:   v1.SchemeGroupVersion.Group,
		Version: v1.SchemeGroupVersion.Version,
		Kind:    "Pod",
	}
	ref := metav1.NewControllerRef(pod, gvk)
	return []metav1.OwnerReference{*ref}
}
