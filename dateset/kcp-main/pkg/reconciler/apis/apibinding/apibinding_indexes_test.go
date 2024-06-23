/*
Copyright 2022 The KCP Authors.

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

package apibinding

import (
	"reflect"
	"testing"

	"github.com/kcp-dev/logicalcluster/v3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apisv1alpha1 "github.com/kcp-dev/kcp/sdk/apis/apis/v1alpha1"
	"github.com/kcp-dev/kcp/sdk/client"
)

func TestIndexAPIExportByAPIResourceSchemas(t *testing.T) {
	tests := map[string]struct {
		obj     interface{}
		want    []string
		wantErr bool
	}{
		"not an APIExport": {
			obj:     "not an APIExport",
			want:    []string{},
			wantErr: true,
		},
		"valid APIExport": {
			obj: &apisv1alpha1.APIExport{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						logicalcluster.AnnotationKey: "root:default",
					},
					Name: "foo",
				},
				Spec: apisv1alpha1.APIExportSpec{
					LatestResourceSchemas: []string{"schema1", "some-other-schema"},
				},
			},
			want: []string{
				client.ToClusterAwareKey(logicalcluster.NewPath("root:default"), "schema1"),
				client.ToClusterAwareKey(logicalcluster.NewPath("root:default"), "some-other-schema"),
			},
			wantErr: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := indexAPIExportsByAPIResourceSchemasFunc(tt.obj)
			if (err != nil) != tt.wantErr {
				t.Errorf("indexAPIExportsByAPIResourceSchemasFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("indexAPIExportsByAPIResourceSchemasFunc() got = %v, want %v", got, tt.want)
			}
		})
	}
}
