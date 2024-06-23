/*
Copyright 2022 The Volcano Authors.

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

package jobtemplate

import (
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	vcclientset "volcano.sh/apis/pkg/client/clientset/versioned"
	versionedscheme "volcano.sh/apis/pkg/client/clientset/versioned/scheme"
	informerfactory "volcano.sh/apis/pkg/client/informers/externalversions"
	batchinformer "volcano.sh/apis/pkg/client/informers/externalversions/batch/v1alpha1"
	flowinformer "volcano.sh/apis/pkg/client/informers/externalversions/flow/v1alpha1"
	batchlister "volcano.sh/apis/pkg/client/listers/batch/v1alpha1"
	flowlister "volcano.sh/apis/pkg/client/listers/flow/v1alpha1"
	"volcano.sh/volcano/pkg/controllers/apis"
	"volcano.sh/volcano/pkg/controllers/framework"
)

func init() {
	framework.RegisterController(&jobtemplatecontroller{})
}

// jobtemplatecontroller the JobTemplate jobtemplatecontroller type.
type jobtemplatecontroller struct {
	kubeClient kubernetes.Interface
	vcClient   vcclientset.Interface

	//informer
	jobTemplateInformer flowinformer.JobTemplateInformer
	jobInformer         batchinformer.JobInformer

	//jobTemplateLister
	jobTemplateLister flowlister.JobTemplateLister
	jobTemplateSynced cache.InformerSynced

	//jobLister
	jobLister batchlister.JobLister
	jobSynced cache.InformerSynced

	// JobTemplate Event recorder
	recorder record.EventRecorder

	queue              workqueue.RateLimitingInterface
	enqueueJobTemplate func(req apis.FlowRequest)

	syncHandler func(req *apis.FlowRequest) error

	maxRequeueNum int
}

func (jt *jobtemplatecontroller) Name() string {
	return "jobtemplate-controller"
}

func (jt *jobtemplatecontroller) Initialize(opt *framework.ControllerOption) error {
	jt.kubeClient = opt.KubeClient
	jt.vcClient = opt.VolcanoClient

	jt.jobTemplateInformer = informerfactory.NewSharedInformerFactory(jt.vcClient, 0).Flow().V1alpha1().JobTemplates()
	jt.jobTemplateSynced = jt.jobTemplateInformer.Informer().HasSynced
	jt.jobTemplateLister = jt.jobTemplateInformer.Lister()
	jt.jobTemplateInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: jt.addJobTemplate,
	})

	jt.jobInformer = informerfactory.NewSharedInformerFactory(jt.vcClient, 0).Batch().V1alpha1().Jobs()
	jt.jobSynced = jt.jobInformer.Informer().HasSynced
	jt.jobLister = jt.jobInformer.Lister()
	jt.jobInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: jt.addJob,
	})

	jt.maxRequeueNum = opt.MaxRequeueNum
	if jt.maxRequeueNum < 0 {
		jt.maxRequeueNum = -1
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&corev1.EventSinkImpl{Interface: jt.kubeClient.CoreV1().Events("")})

	jt.recorder = eventBroadcaster.NewRecorder(versionedscheme.Scheme, v1.EventSource{Component: "vc-controller-manager"})
	jt.queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	jt.enqueueJobTemplate = jt.enqueue

	jt.syncHandler = jt.handleJobTemplate

	return nil
}

func (jt *jobtemplatecontroller) Run(stopCh <-chan struct{}) {
	defer jt.queue.ShutDown()

	go jt.jobTemplateInformer.Informer().Run(stopCh)
	go jt.jobInformer.Informer().Run(stopCh)

	cache.WaitForCacheSync(stopCh, jt.jobSynced, jt.jobTemplateSynced)

	go wait.Until(jt.worker, time.Second, stopCh)

	klog.Infof("JobTemplateController is running ...... ")

	<-stopCh
}

func (jt *jobtemplatecontroller) worker() {
	for jt.processNextWorkItem() {
	}
}

func (jt *jobtemplatecontroller) processNextWorkItem() bool {
	obj, shutdown := jt.queue.Get()
	if shutdown {
		// Stop working
		return false
	}

	// We call Done here so the workqueue knows we have finished
	// processing this item. We also must remember to call Forget if we
	// do not want this work item being re-queued. For example, we do
	// not call Forget if a transient error occurs, instead the item is
	// put back on the workqueue and attempted again after a back-off
	// period.
	defer jt.queue.Done(obj)

	req, ok := obj.(apis.FlowRequest)
	if !ok {
		klog.Errorf("%v is not a valid queue request struct.", obj)
		return true
	}

	err := jt.syncHandler(&req)
	jt.handleJobTemplateErr(err, obj)

	return true
}

func (jt *jobtemplatecontroller) handleJobTemplate(req *apis.FlowRequest) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing jobTemplate %s (%v).", req.JobTemplateName, time.Since(startTime))
	}()

	jobTemplate, err := jt.jobTemplateLister.JobTemplates(req.Namespace).Get(req.JobTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Infof("JobTemplate %s has been deleted.", req.JobTemplateName)
			return nil
		}

		return fmt.Errorf("get jobTemplate %s failed for %v", req.JobFlowName, err)
	}

	klog.V(4).Infof("Begin syncJobTemplate for jobTemplate %s", req.JobFlowName)
	if err := jt.syncJobTemplate(jobTemplate); err != nil {
		return fmt.Errorf("sync jobTemplate %s failed for %v, event is %v, action is %s",
			req.JobFlowName, err, req.Event, req.Action)
	}

	return nil
}

func (jt *jobtemplatecontroller) handleJobTemplateErr(err error, obj interface{}) {
	if err == nil {
		jt.queue.Forget(obj)
		return
	}

	if jt.maxRequeueNum == -1 || jt.queue.NumRequeues(obj) < jt.maxRequeueNum {
		klog.V(4).Infof("Error syncing jobTemplate request %v for %v.", obj, err)
		jt.queue.AddRateLimited(obj)
		return
	}

	req, _ := obj.(*apis.FlowRequest)
	jt.recordEventsForJobTemplate(req.Namespace, req.JobTemplateName, v1.EventTypeWarning, string(req.Action),
		fmt.Sprintf("%v JobTemplate failed for %v", req.Action, err))
	klog.V(2).Infof("Dropping JobTemplate request %v out of the queue for %v.", obj, err)
	jt.queue.Forget(obj)
}

func (jt *jobtemplatecontroller) recordEventsForJobTemplate(namespace, name, eventType, reason, message string) {
	jobTemplate, err := jt.jobTemplateLister.JobTemplates(namespace).Get(name)
	if err != nil {
		klog.Errorf("Get JobTemplate %s failed for %v.", name, err)
		return
	}

	jt.recorder.Event(jobTemplate, eventType, reason, message)
}
