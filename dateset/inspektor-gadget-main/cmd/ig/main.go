// Copyright 2019-2024 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	// Import this early to set the enrivonment variable before any other package is imported
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/environment/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/image"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/ig/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"

	// This is a blank include that actually imports all gadgets
	// TODO: traceloop is imported separately because it is not in all-gadgets
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"

	// Another blank import for the used operator
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/prometheus"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
)

func main() {
	if experimental.Enabled() {
		log.Info("Experimental features enabled")
	}

	rootCmd := &cobra.Command{
		Use:   "ig",
		Short: "Collection of gadgets for containers",
	}
	common.AddVerboseFlag(rootCmd)

	host.AddFlags(rootCmd)

	rootCmd.AddCommand(
		containers.NewListContainersCmd(),
		common.NewVersionCmd(),
	)

	// evaluate flags early; this will make sure that flags for host are evaluated before
	// calling host.Init()
	err := commonutils.ParseEarlyFlags(rootCmd, os.Args[1:])
	if err != nil {
		// Analogous to cobra error message
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	runtime := local.New()
	hiddenColumnTags := []string{"kubernetes"}
	common.AddCommandsFromRegistry(rootCmd, runtime, hiddenColumnTags)

	operators.RegisterDataOperator(ocihandler.OciHandler)

	rootCmd.AddCommand(newDaemonCommand(runtime))
	rootCmd.AddCommand(image.NewImageCmd())
	rootCmd.AddCommand(common.NewLoginCmd())
	rootCmd.AddCommand(common.NewLogoutCmd())
	rootCmd.AddCommand(common.NewRunCommand(rootCmd, runtime, hiddenColumnTags))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
