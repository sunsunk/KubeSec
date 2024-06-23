// Copyright © 2021 Alibaba Group Holding Ltd.
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

package cluster

import (
	"fmt"
	"path"

	"github.com/sealerio/sealer/cmd/sealer/cmd/types"
	"github.com/sealerio/sealer/cmd/sealer/cmd/utils"
	"github.com/sealerio/sealer/pkg/application"
	clusterruntime "github.com/sealerio/sealer/pkg/cluster-runtime"
	"github.com/sealerio/sealer/pkg/clusterfile"
	imagev1 "github.com/sealerio/sealer/pkg/define/image/v1"
	"github.com/sealerio/sealer/pkg/define/options"
	"github.com/sealerio/sealer/pkg/imagedistributor"
	"github.com/sealerio/sealer/pkg/imageengine"
	"github.com/sealerio/sealer/pkg/infradriver"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

var (
	exampleForRollbackCmd = `
  sealer rollback docker.io/sealerio/kubernetes:v1.22.15-rollback
`

	longDescriptionForRollbackCmd = `rollback command is used to rollback a Kubernetes cluster via specified Clusterfile.`
)

func NewRollbackCmd() *cobra.Command {
	rollbackFlags := &types.RollbackFlags{}
	rollbackCmd := &cobra.Command{
		Use:     "rollback",
		Short:   "rollback a Kubernetes cluster via specified Clusterfile",
		Long:    longDescriptionForRollbackCmd,
		Example: exampleForRollbackCmd,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				err error
			)
			if len(args) == 0 {
				return fmt.Errorf("you must input image name")
			}

			imageEngine, err := imageengine.NewImageEngine(options.EngineGlobalConfigurations{})
			if err != nil {
				return err
			}

			id, err := imageEngine.Pull(&options.PullOptions{
				Quiet:      false,
				PullPolicy: "missing",
				Image:      args[0],
				Platform:   "local",
			})
			if err != nil {
				return err
			}

			imageSpec, err := imageEngine.Inspect(&options.InspectOptions{ImageNameOrID: id})
			if err != nil {
				return fmt.Errorf("failed to get cluster image extension: %s", err)
			}

			//get origin cluster
			current, _, err := clusterfile.GetActualClusterFile()
			if err != nil {
				return err
			}
			cluster := current.GetCluster()

			//update image of cluster
			cluster.Spec.APPNames = rollbackFlags.AppNames
			cluster.Spec.Image = args[0]
			clusterData, err := yaml.Marshal(cluster)
			if err != nil {
				return err
			}

			//generate new cluster
			newClusterfile, err := clusterfile.NewClusterFile(clusterData)
			if err != nil {
				return err
			}

			return rollbackCluster(newClusterfile, imageEngine, imageSpec, rollbackFlags)
		},
	}

	rollbackCmd.Flags().StringSliceVar(&rollbackFlags.AppNames, "apps", nil, "override default AppNames of sealer image")
	rollbackCmd.Flags().BoolVar(&rollbackFlags.IgnoreCache, "ignore-cache", false, "whether ignore cache when distribute sealer image, default is false.")

	return rollbackCmd
}

func rollbackCluster(cf clusterfile.Interface, imageEngine imageengine.Interface, imageSpec *imagev1.ImageSpec, rollbackFlags *types.RollbackFlags) error {
	if imageSpec.ImageExtension.Type != imagev1.KubeInstaller {
		return fmt.Errorf("exit rollback process, wrong cluster image type: %s", imageSpec.ImageExtension.Type)
	}

	cluster := cf.GetCluster()
	// merge image extension
	mergedWithExt := utils.MergeClusterWithImageExtension(&cluster, imageSpec.ImageExtension)

	infraDriver, err := infradriver.NewInfraDriver(mergedWithExt)
	if err != nil {
		return err
	}
	clusterHosts := infraDriver.GetHostIPList()

	imageName := infraDriver.GetClusterImageName()

	clusterHostsPlatform, err := infraDriver.GetHostsPlatform(clusterHosts)
	if err != nil {
		return err
	}

	logrus.Infof("start to rollback cluster with image: %s", imageName)

	imageMounter, err := imagedistributor.NewImageMounter(imageEngine, clusterHostsPlatform)
	if err != nil {
		return err
	}

	imageMountInfo, err := imageMounter.Mount(imageName)
	if err != nil {
		return err
	}

	defer func() {
		err = imageMounter.Umount(imageName, imageMountInfo)
		if err != nil {
			logrus.Errorf("failed to umount cluster image")
		}
	}()

	distributor, err := imagedistributor.NewScpDistributor(imageMountInfo, infraDriver, cf.GetConfigs(), imagedistributor.DistributeOption{
		IgnoreCache: rollbackFlags.IgnoreCache,
	})
	if err != nil {
		return err
	}

	pluginFilePath := path.Join(infraDriver.GetClusterRootfsPath(), "plugins")
	plugins, err := clusterruntime.LoadPluginsFromFile(pluginFilePath)
	if err != nil {
		return err
	}

	if cf.GetPlugins() != nil {
		plugins = append(plugins, cf.GetPlugins()...)
	}

	runtimeConfig := &clusterruntime.RuntimeConfig{
		Distributor:            distributor,
		Plugins:                plugins,
		ContainerRuntimeConfig: cluster.Spec.ContainerRuntime,
	}

	rollbacker, err := clusterruntime.NewInstaller(infraDriver, *runtimeConfig, clusterruntime.GetClusterInstallInfo(imageSpec.ImageExtension.Labels, runtimeConfig.ContainerRuntimeConfig))
	if err != nil {
		return err
	}

	//we need to save desired clusterfile to local disk temporarily
	//and will use it later to clean the cluster node if apply failed.
	if err = cf.SaveAll(clusterfile.SaveOptions{}); err != nil {
		return err
	}

	err = rollbacker.Rollback()
	if err != nil {
		return err
	}

	confPath := clusterruntime.GetClusterConfPath(imageSpec.ImageExtension.Labels)
	cmds := infraDriver.GetClusterLaunchCmds()
	appNames := infraDriver.GetClusterLaunchApps()

	// merge to application between v2.ClusterSpec, v2.Application and image extension
	v2App, err := application.NewAppDriver(utils.ConstructApplication(cf.GetApplication(), cmds, appNames, cluster.Spec.Env), imageSpec.ImageExtension)
	if err != nil {
		return fmt.Errorf("failed to parse application from Clusterfile:%v ", err)
	}

	// install application
	if err = v2App.Launch(infraDriver); err != nil {
		return err
	}
	if err = v2App.Save(application.SaveOptions{}); err != nil {
		return err
	}

	//save and commit
	if err = cf.SaveAll(clusterfile.SaveOptions{CommitToCluster: true, ConfPath: confPath}); err != nil {
		return err
	}

	logrus.Infof("succeeded in rollingback cluster with image %s", imageName)

	return nil
}
