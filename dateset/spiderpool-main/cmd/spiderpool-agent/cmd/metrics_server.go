// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/spidernet-io/spiderpool/pkg/constant"
	"github.com/spidernet-io/spiderpool/pkg/metric"
)

// initAgentMetricsServer will start an opentelemetry http server for spiderpool agent.
func initAgentMetricsServer(ctx context.Context) {
	metricController, err := metric.InitMetric(ctx, constant.SpiderpoolAgent,
		agentContext.Cfg.EnableMetric, agentContext.Cfg.EnableDebugLevelMetric)
	if nil != err {
		logger.Fatal(err.Error())
	}

	err = metric.InitSpiderpoolAgentMetrics(ctx)
	if nil != err {
		logger.Fatal(err.Error())
	}

	if agentContext.Cfg.EnableMetric {
		metricsSrv := &http.Server{
			Addr:    fmt.Sprintf(":%s", agentContext.Cfg.MetricHttpPort),
			Handler: metricController,
		}

		go func() {
			if err := metricsSrv.ListenAndServe(); nil != err {
				if err == http.ErrServerClosed {
					return
				}

				logger.Fatal(err.Error())
			}
		}()

		agentContext.MetricsHttpServer = metricsSrv
	}
}
