// Copyright (c) 2023 The Jaeger Authors.
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

package adjuster

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"

	"github.com/jaegertracing/jaeger/model"
)

func TestOTelTagAdjuster(t *testing.T) {
	testCases := []struct {
		description string
		span        *model.Span
		expected    *model.Span
	}{
		{
			description: "span with otel library tags",
			span: &model.Span{
				Tags: model.KeyValues{
					model.String("random_key", "random_value"),
					model.String(string(semconv.OTelLibraryNameKey), "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"),
					model.String(string(semconv.OTelLibraryVersionKey), "0.45.0"),
					model.String("another_key", "another_value"),
				},
				Process: &model.Process{
					Tags: model.KeyValues{},
				},
			},
			expected: &model.Span{
				Tags: model.KeyValues{
					model.String("random_key", "random_value"),
					model.String("another_key", "another_value"),
				},
				Process: &model.Process{
					Tags: model.KeyValues{
						model.String(string(semconv.OTelLibraryNameKey), "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"),
						model.String(string(semconv.OTelLibraryVersionKey), "0.45.0"),
					},
				},
			},
		},
		{
			description: "span without otel library tags",
			span: &model.Span{
				Tags: model.KeyValues{
					model.String("random_key", "random_value"),
				},
				Process: &model.Process{
					Tags: model.KeyValues{},
				},
			},
			expected: &model.Span{
				Tags: model.KeyValues{
					model.String("random_key", "random_value"),
				},
				Process: &model.Process{
					Tags: model.KeyValues{},
				},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			beforeTags := testCase.span.Tags

			trace := &model.Trace{
				Spans: []*model.Span{testCase.span},
			}
			trace, err := OTelTagAdjuster().Adjust(trace)
			require.NoError(t, err)
			assert.Equal(t, testCase.expected.Tags, trace.Spans[0].Tags)
			assert.Equal(t, testCase.expected.Process.Tags, trace.Spans[0].Process.Tags)

			newTag := model.String("new_key", "new_value")
			beforeTags[0] = newTag
			assert.Equal(t, newTag, testCase.span.Tags[0], "span.Tags still points to the same underlying array")
		})
	}
}
