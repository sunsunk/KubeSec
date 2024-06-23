/*
Copyright 2020 The SuperEdge Authors.

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

package main

import (
	goflag "flag"
	"math/rand"
	"os"
	"time"

	"k8s.io/klog/v2"

	"github.com/superedge/superedge/cmd/site-manager/app"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	goflag.Set("alsologtostderr", "true")
	klogFlags := goflag.NewFlagSet("klog", goflag.ExitOnError)
	klog.InitFlags(klogFlags)

	defer klog.Flush()

	command := app.NewSiteManagerDaemonCommand()

	command.Flags().SortFlags = false
	command.Flags().AddGoFlagSet(klogFlags)

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}
