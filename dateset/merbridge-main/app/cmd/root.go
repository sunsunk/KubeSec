/*
Copyright © 2022 Merbridge Authors

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

package cmd

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/controller"
	cniserver "github.com/merbridge/merbridge/internal/cni-server"
	"github.com/merbridge/merbridge/internal/ebpfs"
	"github.com/merbridge/merbridge/internal/process"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mbctl",
	Short: "Use eBPF to speed up your Service Mesh like crossing an Einstein-Rosen Bridge.",
	Long:  `Use eBPF to speed up your Service Mesh like crossing an Einstein-Rosen Bridge.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ebpfs.LoadMBProgs(config.Mode, config.UseReconnect, config.EnableCNI, config.Debug); err != nil {
			return fmt.Errorf("failed to load ebpf programs: %v", err)
		}
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("remove memlock error: %v", err)
		}

		stop := make(chan struct{}, 1)
		cniReady := make(chan struct{}, 1)
		if config.EnableCNI {
			s := cniserver.NewServer(config.Mode, path.Join(config.HostVarRun, "merbridge-cni.sock"),
				"/sys/fs/bpf", cniReady, stop)
			if err := s.Start(); err != nil {
				log.Fatal(err)
				return err
			}
		}
		var pw process.ProcessManager
		var err error
		if config.EnableAmbientMode {
			pw, err = process.NewProcessManager("")
			if err != nil {
				panic(err)
			}
			go func() {
				err := pw.Run(stop)
				if err != nil {
					panic(err)
				}
			}()
		}
		// todo: wait for stop
		if err := controller.Run(cniReady, pw, stop); err != nil {
			log.Fatal(err)
			return err
		}
		return nil
	},
}

// Execute executes root command and its child commands
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Setup log format
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp:       false,
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		DisableColors:          true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			fs := strings.Split(f.File, "/")
			filename := fs[len(fs)-1]
			ff := strings.Split(f.Function, "/")
			_f := ff[len(ff)-1]
			return fmt.Sprintf("%s()", _f), fmt.Sprintf("%s:%d", filename, f.Line)
		},
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)

	// Get some flags from commands
	rootCmd.PersistentFlags().StringVarP(&config.Mode, "mode", "m", config.ModeIstio, "Service mesh mode, current support istio, linkerd, kuma and osm")
	rootCmd.PersistentFlags().BoolVarP(&config.UseReconnect, "use-reconnect", "r", true, "Use re-connect mode for same-node acceleration")
	rootCmd.PersistentFlags().BoolVarP(&config.Debug, "debug", "d", false, "Debug mode")
	rootCmd.PersistentFlags().BoolVarP(&config.IsKind, "kind", "k", false, "Enable when Kubernetes is running in Kind")
	rootCmd.PersistentFlags().StringVarP(&config.IpsFile, "ips-file", "f", "", "Current node IPs filename")
	_ = rootCmd.PersistentFlags().MarkDeprecated("ips-file", "no need to collect node IPs")
	rootCmd.PersistentFlags().BoolVar(&config.EnableCNI, "cni-mode", false, "Enable Merbridge CNI plugin")
	rootCmd.PersistentFlags().StringVar(&config.HostProc, "host-proc", "/host/proc", "/proc mount path")
	rootCmd.PersistentFlags().StringVar(&config.CNIBinDir, "cni-bin-dir", "/host/opt/cni/bin", "/opt/cni/bin mount path")
	rootCmd.PersistentFlags().StringVar(&config.CNIConfigDir, "cni-config-dir", "/host/etc/cni/net.d", "/etc/cni/net.d mount path")
	rootCmd.PersistentFlags().StringVar(&config.HostVarRun, "host-var-run", "/host/var/run", "/var/run mount path")
	rootCmd.PersistentFlags().StringVar(&config.KubeConfig, "kubeconfig", "", "Kubernetes configuration file")
	rootCmd.PersistentFlags().StringVar(&config.Context, "kubecontext", "", "The name of the kube config context to use")
	rootCmd.PersistentFlags().BoolVar(&config.EnableHotRestart, "enable-hot-restart", false, "enable hot restart")
	rootCmd.PersistentFlags().BoolVar(&config.EnableAmbientMode, "enable-ambient-mode", false, "enable istio ambient mode support")
}
