// Copyright 2019-2022 The Inspektor Gadget authors
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

package advise

import (
	"github.com/spf13/cobra"

	commonadvise "github.com/inspektor-gadget/inspektor-gadget/cmd/common/advise"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
)

// All the gadgets within this package use this global variable, so let's
// declare it here.
var (
	params          utils.CommonFlags
	gadgetNamespace string
)

func NewAdviseCmd(gadgetNamespaceIn string) *cobra.Command {
	gadgetNamespace = gadgetNamespaceIn
	cmd := commonadvise.NewCommonAdviseCmd()

	cmd.AddCommand(newNetworkPolicyCmd(gadgetNamespace))
	cmd.AddCommand(newSeccompProfileCmd(gadgetNamespace))

	return cmd
}
