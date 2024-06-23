/*
Copyright 2018 The Volcano Authors.

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

package app

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	v1 "k8s.io/api/core/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"

	"volcano.sh/apis/pkg/apis/helpers"
	"volcano.sh/apis/pkg/apis/scheduling/scheme"
	"volcano.sh/volcano/cmd/webhook-manager/app/options"
	"volcano.sh/volcano/pkg/kube"
	commonutil "volcano.sh/volcano/pkg/util"
	"volcano.sh/volcano/pkg/version"
	wkconfig "volcano.sh/volcano/pkg/webhooks/config"
	"volcano.sh/volcano/pkg/webhooks/router"
)

// Run start the service of admission controller.
func Run(config *options.Config) error {
	if config.PrintVersion {
		version.PrintVersionAndExit()
		return nil
	}

	if config.EnableHealthz {
		if err := helpers.StartHealthz(config.HealthzBindAddress, "volcano-admission", config.CaCertData, config.CertData, config.KeyData); err != nil {
			return err
		}
	}

	if config.WebhookURL == "" && config.WebhookNamespace == "" && config.WebhookName == "" {
		return fmt.Errorf("failed to start webhooks as both 'url' and 'namespace/name' of webhook are empty")
	}

	restConfig, err := kube.BuildConfig(config.KubeClientOptions)
	if err != nil {
		return fmt.Errorf("unable to build k8s config: %v", err)
	}

	admissionConf := wkconfig.LoadAdmissionConf(config.ConfigPath)
	if admissionConf == nil {
		klog.Errorf("loadAdmissionConf failed.")
	} else {
		klog.V(2).Infof("loadAdmissionConf:%v", admissionConf.ResGroupsConfig)
	}

	vClient := getVolcanoClient(restConfig)
	kubeClient := getKubeClient(restConfig)

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&corev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: commonutil.GenerateComponentName(config.SchedulerNames)})
	if err := router.ForEachAdmission(config, func(service *router.AdmissionService) error {
		if service.Config != nil {
			service.Config.VolcanoClient = vClient
			service.Config.KubeClient = kubeClient
			service.Config.SchedulerNames = config.SchedulerNames
			service.Config.Recorder = recorder
			service.Config.ConfigData = admissionConf
		}

		klog.V(3).Infof("Registered '%s' as webhook.", service.Path)
		http.HandleFunc(service.Path, service.Handler)

		klog.V(3).Infof("Add CaCert for webhook <%s>", service.Path)
		if err = addCaCertForWebhook(kubeClient, service, config.CaCertData); err != nil {
			return fmt.Errorf("failed to add caCert for webhook %v", err)
		}
		return nil
	}); err != nil {
		return err
	}

	klog.V(3).Infof("Successfully added caCert for all webhooks")

	webhookServeError := make(chan struct{})
	stopChannel := make(chan os.Signal, 1)
	signal.Notify(stopChannel, syscall.SIGTERM, syscall.SIGINT)

	server := &http.Server{
		Addr:      config.ListenAddress + ":" + strconv.Itoa(config.Port),
		TLSConfig: configTLS(config, restConfig),
	}
	go func() {
		err = server.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			klog.Fatalf("ListenAndServeTLS for admission webhook failed: %v", err)
			close(webhookServeError)
		}

		klog.Info("Volcano Webhook manager started.")
	}()

	if config.ConfigPath != "" {
		go wkconfig.WatchAdmissionConf(config.ConfigPath, stopChannel)
	}

	select {
	case <-stopChannel:
		if err := server.Close(); err != nil {
			return fmt.Errorf("close admission server failed: %v", err)
		}
		return nil
	case <-webhookServeError:
		return fmt.Errorf("unknown webhook server error")
	}
}
