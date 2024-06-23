// Copyright 2021 Chaos Mesh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import "testing"

func Test_lowercaseCamelCase(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "common",
			args: args{
				str: "PodChaos",
			},
			want: "podChaos",
		}, {
			name: "ALLCAP",
			args: args{
				str: "DNSChaos",
			},
			want: "dnsChaos",
		}, {
			name: "ALLCAP",
			args: args{
				str: "JVMChaos",
			},
			want: "jvmChaos",
		}, {
			name: "workflow",
			args: args{
				str: "Workflow",
			},
			want: "workflow",
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lowercaseCamelCase(tt.args.str); got != tt.want {
				t.Errorf("lowercaseCamelCase() = %v, want %v", got, tt.want)
			}
		})
	}
}
