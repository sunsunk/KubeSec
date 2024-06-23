// Copyright (c) 2019 The Jaeger Authors.
// Copyright (c) 2017 Uber Technologies, Inc.
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

package integration

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	elasticsearch8 "github.com/elastic/go-elasticsearch/v8"
	"github.com/olivere/elastic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/jaegertracing/jaeger/model"
	estemplate "github.com/jaegertracing/jaeger/pkg/es"
	eswrapper "github.com/jaegertracing/jaeger/pkg/es/wrapper"
	"github.com/jaegertracing/jaeger/pkg/metrics"
	"github.com/jaegertracing/jaeger/pkg/testutils"
	"github.com/jaegertracing/jaeger/plugin/storage/es/dependencystore"
	"github.com/jaegertracing/jaeger/plugin/storage/es/mappings"
	"github.com/jaegertracing/jaeger/plugin/storage/es/samplingstore"
	"github.com/jaegertracing/jaeger/plugin/storage/es/spanstore"
)

const (
	host                     = "0.0.0.0"
	queryPort                = "9200"
	queryHostPort            = host + ":" + queryPort
	queryURL                 = "http://" + queryHostPort
	indexPrefix              = "integration-test"
	indexDateLayout          = "2006-01-02"
	tagKeyDeDotChar          = "@"
	maxSpanAge               = time.Hour * 72
	defaultMaxDocCount       = 10_000
	spanTemplateName         = "jaeger-span"
	serviceTemplateName      = "jaeger-service"
	dependenciesTemplateName = "jaeger-dependencies"
)

type ESStorageIntegration struct {
	StorageIntegration

	client        *elastic.Client
	v8Client      *elasticsearch8.Client
	bulkProcessor *elastic.BulkProcessor
	logger        *zap.Logger
}

func (s *ESStorageIntegration) tracerProvider() (trace.TracerProvider, *tracetest.InMemoryExporter, func()) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(exporter),
	)
	closer := func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			s.logger.Error("failed to close tracer", zap.Error(err))
		}
	}
	return tp, exporter, closer
}

func (s *ESStorageIntegration) getVersion() (uint, error) {
	pingResult, _, err := s.client.Ping(queryURL).Do(context.Background())
	if err != nil {
		return 0, err
	}
	esVersion, err := strconv.Atoi(string(pingResult.Version.Number[0]))
	if err != nil {
		return 0, err
	}
	// OpenSearch is based on ES 7.x
	if strings.Contains(pingResult.TagLine, "OpenSearch") {
		if pingResult.Version.Number[0] == '1' || pingResult.Version.Number[0] == '2' {
			esVersion = 7
		}
	}
	return uint(esVersion), nil
}

func (s *ESStorageIntegration) initializeES(t *testing.T, allTagsAsFields, archive bool) error {
	rawClient, err := elastic.NewClient(
		elastic.SetURL(queryURL),
		elastic.SetSniff(false))
	require.NoError(t, err)
	s.logger, _ = testutils.NewLogger()

	s.client = rawClient
	s.v8Client, err = elasticsearch8.NewClient(elasticsearch8.Config{
		Addresses:            []string{queryURL},
		DiscoverNodesOnStart: false,
	})
	require.NoError(t, err)

	s.initSpanstore(t, allTagsAsFields, archive)
	s.initSamplingStore(t)

	s.CleanUp = func() error {
		s.esCleanUp(t, allTagsAsFields, archive)
		return nil
	}
	s.Refresh = s.esRefresh
	s.esCleanUp(t, allTagsAsFields, archive)
	// TODO: remove this flag after ES support returning spanKind when get operations
	s.GetOperationsMissingSpanKind = true
	return nil
}

func (s *ESStorageIntegration) esCleanUp(t *testing.T, allTagsAsFields, archive bool) {
	_, err := s.client.DeleteIndex("*").Do(context.Background())
	require.NoError(t, err)
	s.initSpanstore(t, allTagsAsFields, archive)
}

func (s *ESStorageIntegration) initSamplingStore(t *testing.T) {
	client := s.getEsClient(t)
	mappingBuilder := mappings.MappingBuilder{
		TemplateBuilder: estemplate.TextTemplateBuilder{},
		Shards:          5,
		Replicas:        1,
		EsVersion:       client.GetVersion(),
		IndexPrefix:     indexPrefix,
		UseILM:          false,
	}
	clientFn := func() estemplate.Client { return client }
	samplingstore := samplingstore.NewSamplingStore(
		samplingstore.SamplingStoreParams{
			Client:          clientFn,
			Logger:          s.logger,
			IndexPrefix:     indexPrefix,
			IndexDateLayout: indexDateLayout,
			MaxDocCount:     defaultMaxDocCount,
		})
	sampleMapping, err := mappingBuilder.GetSamplingMappings()
	require.NoError(t, err)
	err = samplingstore.CreateTemplates(sampleMapping)
	require.NoError(t, err)
	s.SamplingStore = samplingstore
}

func (s *ESStorageIntegration) getEsClient(t *testing.T) eswrapper.ClientWrapper {
	bp, err := s.client.BulkProcessor().BulkActions(1).FlushInterval(time.Nanosecond).Do(context.Background())
	require.NoError(t, err)
	s.bulkProcessor = bp
	esVersion, err := s.getVersion()
	require.NoError(t, err)
	return eswrapper.WrapESClient(s.client, bp, esVersion, s.v8Client)
}

func (s *ESStorageIntegration) initSpanstore(t *testing.T, allTagsAsFields, archive bool) error {
	client := s.getEsClient(t)
	mappingBuilder := mappings.MappingBuilder{
		TemplateBuilder: estemplate.TextTemplateBuilder{},
		Shards:          5,
		Replicas:        1,
		EsVersion:       client.GetVersion(),
		IndexPrefix:     indexPrefix,
		UseILM:          false,
	}
	spanMapping, serviceMapping, err := mappingBuilder.GetSpanServiceMappings()
	require.NoError(t, err)
	clientFn := func() estemplate.Client { return client }

	w := spanstore.NewSpanWriter(
		spanstore.SpanWriterParams{
			Client:            clientFn,
			Logger:            s.logger,
			MetricsFactory:    metrics.NullFactory,
			IndexPrefix:       indexPrefix,
			AllTagsAsFields:   allTagsAsFields,
			TagDotReplacement: tagKeyDeDotChar,
			Archive:           archive,
		})
	err = w.CreateTemplates(spanMapping, serviceMapping, indexPrefix)
	require.NoError(t, err)
	tracer, _, closer := s.tracerProvider()
	defer closer()
	s.SpanWriter = w
	s.SpanReader = spanstore.NewSpanReader(spanstore.SpanReaderParams{
		Client:            clientFn,
		Logger:            s.logger,
		MetricsFactory:    metrics.NullFactory,
		IndexPrefix:       indexPrefix,
		MaxSpanAge:        maxSpanAge,
		TagDotReplacement: tagKeyDeDotChar,
		Archive:           archive,
		MaxDocCount:       defaultMaxDocCount,
		Tracer:            tracer.Tracer("test"),
	})
	dependencyStore := dependencystore.NewDependencyStore(dependencystore.DependencyStoreParams{
		Client:          clientFn,
		Logger:          s.logger,
		IndexPrefix:     indexPrefix,
		IndexDateLayout: indexDateLayout,
		MaxDocCount:     defaultMaxDocCount,
	})

	depMapping, err := mappingBuilder.GetDependenciesMappings()
	require.NoError(t, err)
	err = dependencyStore.CreateTemplates(depMapping)
	require.NoError(t, err)
	s.DependencyReader = dependencyStore
	s.DependencyWriter = dependencyStore
	return nil
}

func (s *ESStorageIntegration) esRefresh() error {
	err := s.bulkProcessor.Flush()
	if err != nil {
		return err
	}
	_, err = s.client.Refresh().Do(context.Background())
	return err
}

func healthCheck() error {
	for i := 0; i < 200; i++ {
		if _, err := http.Get(queryURL); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("elastic search is not ready")
}

func testElasticsearchStorage(t *testing.T, allTagsAsFields, archive bool) {
	if os.Getenv("STORAGE") != "elasticsearch" && os.Getenv("STORAGE") != "opensearch" {
		t.Skip("Integration test against ElasticSearch skipped; set STORAGE env var to elasticsearch to run this")
	}
	if err := healthCheck(); err != nil {
		t.Fatal(err)
	}
	s := &ESStorageIntegration{}
	s.initializeES(t, allTagsAsFields, archive)

	s.Fixtures = LoadAndParseQueryTestCases(t, "fixtures/queries_es.json")

	if archive {
		t.Run("ArchiveTrace", s.testArchiveTrace)
	} else {
		s.IntegrationTestAll(t)
	}
}

func TestElasticsearchStorage(t *testing.T) {
	testElasticsearchStorage(t, false, false)
}

func TestElasticsearchStorage_AllTagsAsObjectFields(t *testing.T) {
	testElasticsearchStorage(t, true, false)
}

func TestElasticsearchStorage_Archive(t *testing.T) {
	testElasticsearchStorage(t, false, true)
}

func TestElasticsearchStorage_IndexTemplates(t *testing.T) {
	if os.Getenv("STORAGE") != "elasticsearch" {
		t.Skip("Integration test against ElasticSearch skipped; set STORAGE env var to elasticsearch to run this")
	}
	if err := healthCheck(); err != nil {
		t.Fatal(err)
	}
	s := &ESStorageIntegration{}
	s.initializeES(t, true, false)
	esVersion, err := s.getVersion()
	require.NoError(t, err)
	// TODO abstract this into pkg/es/client.IndexManagementLifecycleAPI
	if esVersion <= 7 {
		serviceTemplateExists, err := s.client.IndexTemplateExists(indexPrefix + "-jaeger-service").Do(context.Background())
		require.NoError(t, err)
		assert.True(t, serviceTemplateExists)
		spanTemplateExists, err := s.client.IndexTemplateExists(indexPrefix + "-jaeger-span").Do(context.Background())
		require.NoError(t, err)
		assert.True(t, spanTemplateExists)
	} else {
		serviceTemplateExistsResponse, err := s.v8Client.API.Indices.ExistsIndexTemplate(indexPrefix + "-jaeger-service")
		require.NoError(t, err)
		assert.Equal(t, 200, serviceTemplateExistsResponse.StatusCode)
		spanTemplateExistsResponse, err := s.v8Client.API.Indices.ExistsIndexTemplate(indexPrefix + "-jaeger-span")
		require.NoError(t, err)
		assert.Equal(t, 200, spanTemplateExistsResponse.StatusCode)
	}
	s.cleanESIndexTemplates(t, indexPrefix)
}

func (s *ESStorageIntegration) testArchiveTrace(t *testing.T) {
	defer s.cleanUp(t)
	tID := model.NewTraceID(uint64(11), uint64(22))
	expected := &model.Span{
		OperationName: "archive_span",
		StartTime:     time.Now().Add(-maxSpanAge * 5),
		TraceID:       tID,
		SpanID:        model.NewSpanID(55),
		References:    []model.SpanRef{},
		Process:       model.NewProcess("archived_service", model.KeyValues{}),
	}

	require.NoError(t, s.SpanWriter.WriteSpan(context.Background(), expected))
	s.refresh(t)

	var actual *model.Trace
	found := s.waitForCondition(t, func(t *testing.T) bool {
		var err error
		actual, err = s.SpanReader.GetTrace(context.Background(), tID)
		return err == nil && len(actual.Spans) == 1
	})
	if !assert.True(t, found) {
		CompareTraces(t, &model.Trace{Spans: []*model.Span{expected}}, actual)
	}
}

func (s *ESStorageIntegration) cleanESIndexTemplates(t *testing.T, prefix string) error {
	version, err := s.getVersion()
	require.NoError(t, err)
	if version > 7 {
		prefixWithSeparator := prefix
		if prefix != "" {
			prefixWithSeparator += "-"
		}
		_, err := s.v8Client.Indices.DeleteIndexTemplate(prefixWithSeparator + spanTemplateName)
		require.NoError(t, err)
		_, err = s.v8Client.Indices.DeleteIndexTemplate(prefixWithSeparator + serviceTemplateName)
		require.NoError(t, err)
		_, err = s.v8Client.Indices.DeleteIndexTemplate(prefixWithSeparator + dependenciesTemplateName)
		require.NoError(t, err)
	} else {
		_, err := s.client.IndexDeleteTemplate("*").Do(context.Background())
		require.NoError(t, err)
	}
	return nil
}
