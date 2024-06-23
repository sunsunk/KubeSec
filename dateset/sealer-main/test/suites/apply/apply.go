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

package apply

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sealerio/sealer/common"
	"github.com/sealerio/sealer/pkg/checker"
	k "github.com/sealerio/sealer/pkg/client/k8s"
	"github.com/sealerio/sealer/pkg/infra"
	"github.com/sealerio/sealer/test/testhelper"
	"github.com/sealerio/sealer/test/testhelper/client/k8s"
	"github.com/sealerio/sealer/test/testhelper/settings"
	"github.com/sealerio/sealer/types/api/constants"
	v1 "github.com/sealerio/sealer/types/api/v1"
	"github.com/sealerio/sealer/utils"
	"github.com/sealerio/sealer/utils/exec"
	"github.com/sealerio/sealer/utils/os"

	"github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func getFixtures() string {
	pwd := settings.DefaultTestEnvDir
	return filepath.Join(pwd, "suites", "apply", "fixtures")
}

func GetRawClusterFilePath() string {
	fixtures := getFixtures()
	return filepath.Join(fixtures, "cluster_file_for_test.yaml")
}

func GetRawConfigPluginFilePath() string {
	fixtures := getFixtures()
	return filepath.Join(fixtures, "config_plugin_for_test.yaml")
}

func DeleteClusterByFile(clusterFile string) {
	testhelper.RunCmdAndCheckResult(SealerDeleteCmd(clusterFile), 0)
}

func WriteClusterFileToDisk(cluster *v1.Cluster, clusterFilePath string) {
	testhelper.CheckNotNil(cluster)
	//convert clusterfilev1 to clusterfilev2
	clusterv2 := utils.ConvertV1ClusterToV2Cluster(cluster)
	clusterv2.Spec.Env = []string{"env=TestEnv"}
	err := testhelper.MarshalYamlToFile(clusterFilePath, clusterv2)
	testhelper.CheckErr(err)
}

func LoadClusterFileFromDisk(clusterFilePath string) *v1.Cluster {
	cluster, err := utils.DecodeV1ClusterFromFile(clusterFilePath)
	testhelper.CheckErr(err)
	testhelper.CheckNotNil(cluster)
	return cluster
}

func LoadConfigFromDisk(clusterFilePath string) []v1.Config {
	configs, err := utils.DecodeCRDFromFile(clusterFilePath, constants.ConfigKind)
	testhelper.CheckErr(err)
	testhelper.CheckNotNil(configs)
	return configs.([]v1.Config)
}

func LoadPluginFromDisk(clusterFilePath string) []v1.Plugin {
	plugins, err := utils.DecodeCRDFromFile(clusterFilePath, constants.PluginKind)
	testhelper.CheckErr(err)
	testhelper.CheckNotNil(plugins)
	return plugins.([]v1.Plugin)
}

func GenerateClusterfile(clusterfile string) {
	fp := GetRawConfigPluginFilePath()
	cluster := LoadClusterFileFromDisk(clusterfile)
	//convert clusterfilev1 to clusterfilev2
	clusterv2 := utils.ConvertV1ClusterToV2Cluster(cluster)
	clusterv2.Spec.Env = []string{"env=TestEnv"}
	data, err := yaml.Marshal(clusterv2)
	testhelper.CheckErr(err)
	appendData := [][]byte{data}
	plugins := LoadPluginFromDisk(fp)
	configs := LoadConfigFromDisk(fp)
	for _, plugin := range plugins {
		if plugin.Spec.Type == common.LABEL {
			pluginData := "\n"
			for _, ip := range cluster.Spec.Masters.IPList {
				pluginData += fmt.Sprintf(" %s sealer-test=true \n", ip)
			}
			plugin.Spec.Data = pluginData
		}
		if plugin.Spec.Type == common.HOSTNAME {
			pluginData := "\n"
			for i, ip := range cluster.Spec.Masters.IPList {
				pluginData += fmt.Sprintf("%s master-%s\n", ip, strconv.Itoa(i))
			}
			for i, ip := range cluster.Spec.Nodes.IPList {
				pluginData += fmt.Sprintf("%s node-%s\n", ip, strconv.Itoa(i))
			}
			plugin.Spec.Data = pluginData
		}
		if plugin.Spec.Type == common.TAINT {
			pluginData := "\n"
			for _, ip := range cluster.Spec.Masters.IPList {
				pluginData += fmt.Sprintf("%s node-role.kubernetes.io/master:NoSchedule-\n", ip)
			}
			for _, ip := range cluster.Spec.Nodes.IPList {
				pluginData += fmt.Sprintf("%s sealer-test=true:NoSchedule\n", ip)
			}
			plugin.Spec.Data = pluginData
		}
		data, err := yaml.Marshal(plugin)
		testhelper.CheckErr(err)
		appendData = append(appendData, []byte("---\n"), data)
	}
	for _, config := range configs {
		data, err := yaml.Marshal(config)
		testhelper.CheckErr(err)
		appendData = append(appendData, []byte("---\n"), data)
	}
	err = os.NewCommonWriter(clusterfile).WriteFile(bytes.Join(appendData, []byte("")))
	testhelper.CheckErr(err)
}

func SealerDeleteCmd(clusterFile string) string {
	return fmt.Sprintf("%s delete -f %s --force -d", settings.DefaultSealerBin, clusterFile)
}

func SealerDeleteAll() string {
	return fmt.Sprintf("%s delete --all --force -d", settings.DefaultSealerBin)
}

func SealerDeleteNodeCmd(ip string) string {
	return fmt.Sprintf("%s delete -n %s --force -d", settings.DefaultSealerBin, ip)
}

func SealerApplyCmd(clusterFile string) string {
	return fmt.Sprintf("%s apply -f %s --force -d", settings.DefaultSealerBin, clusterFile)
}

func SealerRunCmd(masters, nodes, passwd string, provider string) string {
	if masters != "" {
		masters = fmt.Sprintf("-m %s", masters)
	}
	if nodes != "" {
		nodes = fmt.Sprintf("-n %s", nodes)
	}
	if passwd != "" {
		passwd = fmt.Sprintf("-p %s", passwd)
	}
	if provider != "" {
		provider = fmt.Sprintf("--provider %s", provider)
	}
	return fmt.Sprintf("%s run %s %s %s %s %s -d", settings.DefaultSealerBin, settings.TestImageName, masters, nodes, passwd, provider)
}

func SealerRun(masters, nodes, passwd, provider string) {
	testhelper.RunCmdAndCheckResult(SealerRunCmd(masters, nodes, passwd, provider), 0)
}

func SealerJoinCmd(masters, nodes string) string {
	if masters != "" {
		masters = fmt.Sprintf("-m %s", masters)
	}
	if nodes != "" {
		nodes = fmt.Sprintf("-n %s", nodes)
	}
	return fmt.Sprintf("%s join %s %s -d", settings.DefaultSealerBin, masters, nodes)
}

func SealerJoin(masters, nodes string) {
	testhelper.RunCmdAndCheckResult(SealerJoinCmd(masters, nodes), 0)
}

func CreateContainerInfraAndSave(cluster *v1.Cluster, clusterFile string) *v1.Cluster {
	CreateContainerInfra(cluster)
	//save used cluster file
	cluster.Spec.Provider = settings.BAREMETAL
	MarshalClusterToFile(clusterFile, cluster)
	cluster.Spec.Provider = settings.CONTAINER
	return cluster
}

func ChangeMasterOrderAndSave(cluster *v1.Cluster, clusterFile string) *v1.Cluster {
	cluster.Spec.Masters.Count = strconv.Itoa(3)
	CreateContainerInfra(cluster)
	//change master order and save used cluster file
	cluster.Spec.Masters.IPList[0], cluster.Spec.Masters.IPList[1] = cluster.Spec.Masters.IPList[1], cluster.Spec.Masters.IPList[0]
	cluster.Spec.Provider = settings.BAREMETAL
	MarshalClusterToFile(clusterFile, cluster)
	cluster.Spec.Provider = settings.CONTAINER
	return cluster
}

func CreateContainerInfra(cluster *v1.Cluster) {
	cluster.DeletionTimestamp = nil
	infraManager, err := infra.NewDefaultProvider(cluster)
	testhelper.CheckErr(err)
	err = infraManager.Apply()
	testhelper.CheckErr(err)
}

func SendAndApplyCluster(sshClient *testhelper.SSHClient, clusterFile string) {
	SendAndRemoteExecCluster(sshClient, clusterFile, SealerApplyCmd(clusterFile))
}

func SendAndJoinCluster(sshClient *testhelper.SSHClient, clusterFile string, joinMasters, joinNodes string) {
	SendAndRemoteExecCluster(sshClient, clusterFile, SealerJoinCmd(joinMasters, joinNodes))
}

func SendAndRunCluster(sshClient *testhelper.SSHClient, clusterFile string, joinMasters, joinNodes, passwd string) {
	SendAndRemoteExecCluster(sshClient, clusterFile, SealerRunCmd(joinMasters, joinNodes, passwd, ""))
}

func SendAndRemoteExecCluster(sshClient *testhelper.SSHClient, clusterFile string, remoteCmd string) {
	// send tmp cluster file to remote server and run apply cmd
	gomega.Eventually(func() bool {
		err := sshClient.SSH.Copy(sshClient.RemoteHostIP, clusterFile, clusterFile)
		return err == nil
	}, settings.MaxWaiteTime).Should(gomega.BeTrue())
	err := sshClient.SSH.CmdAsync(sshClient.RemoteHostIP, nil, remoteCmd)
	testhelper.CheckErr(err)
}

func CleanUpContainerInfra(cluster *v1.Cluster) {
	if cluster == nil {
		return
	}
	if cluster.Spec.Provider != settings.CONTAINER {
		cluster.Spec.Provider = settings.CONTAINER
	}
	t := metav1.Now()
	cluster.DeletionTimestamp = &t
	infraManager, err := infra.NewDefaultProvider(cluster)
	testhelper.CheckErr(err)
	err = infraManager.Apply()
	testhelper.CheckErr(err)
}

// CheckNodeNumWithSSH check node num of remote cluster
func CheckNodeNumWithSSH(client *k8s.Client, expectNum int) {
	if client == nil {
		return
	}
	nodes, err := client.ListNodes()
	testhelper.CheckErr(err)
	num := len(nodes.Items)
	testhelper.CheckEqual(num, expectNum)
}

// CheckNodeNumLocally check node num of local cluster
func CheckNodeNumLocally(client *k.Client, expectNum int) {
	if client == nil {
		return
	}
	nodes, err := client.ListNodes()
	testhelper.CheckErr(err)
	num := len(nodes.Items)
	testhelper.CheckEqual(num, expectNum)
}

func WaitAllNodeRunning() {
	time.Sleep(30 * time.Second)
	err := utils.Retry(10, 5*time.Second, func() error {
		return checker.NewNodeChecker().Check(nil, checker.PhasePost)
	})
	testhelper.CheckErr(err)
}

func WaitAllNodeRunningBySSH(client *k8s.Client) {
	time.Sleep(30 * time.Second)
	err := utils.Retry(10, 5*time.Second, func() error {
		flag, err := client.CheckAllNodeReady()
		if err != nil {
			return err
		}
		if !flag {
			err = client.OutputNotReadyPodInfo()
			if err != nil {
				return err
			}
			return fmt.Errorf("node not ready")
		}
		return nil
	})
	testhelper.CheckErr(err)
}

func MarshalClusterToFile(ClusterFile string, cluster *v1.Cluster) {
	err := testhelper.MarshalYamlToFile(ClusterFile, &cluster)
	testhelper.CheckErr(err)
	testhelper.CheckNotNil(cluster)
}

func CheckDockerAndSwapOff() {
	_, err := exec.RunSimpleCmd("docker -v")
	testhelper.CheckErr(err)
	_, err = exec.RunSimpleCmd("swapoff -a")
	testhelper.CheckErr(err)
}
