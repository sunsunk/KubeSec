// Copyright 2022-2024 The Inspektor Gadget authors
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

/*
Package gadgetcontext handles initializing gadgets and installed operators before
handing them over to a specified runtime.
*/
package gadgetcontext

import (
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

// GadgetContext handles running gadgets by the gadget interface; it orchestrates the whole lifecycle of the gadget
// instance and communicates with gadget and runtime.
type GadgetContext struct {
	ctx                      context.Context
	cancel                   context.CancelFunc
	id                       string
	gadget                   gadgets.GadgetDesc
	gadgetParams             *params.Params
	args                     []string
	runtime                  runtime.Runtime
	runtimeParams            *params.Params
	parser                   parser.Parser
	operators                operators.Operators
	operatorsParamCollection params.Collection
	logger                   logger.Logger
	result                   []byte
	resultError              error
	timeout                  time.Duration
	gadgetInfo               *runTypes.GadgetInfo

	lock             sync.Mutex
	dataSources      map[string]datasource.DataSource
	dataOperators    []operators.DataOperator
	vars             map[string]any
	params           []*api.Param
	prepareCallbacks []func()
	loaded           bool
	imageName        string
	metadata         []byte
}

func New(
	ctx context.Context,
	id string,
	runtime runtime.Runtime,
	runtimeParams *params.Params,
	gadget gadgets.GadgetDesc,
	gadgetParams *params.Params,
	args []string,
	operatorsParamCollection params.Collection,
	parser parser.Parser,
	logger logger.Logger,
	timeout time.Duration,
	gadgetInfo *runTypes.GadgetInfo,
) *GadgetContext {
	gCtx, cancel := context.WithCancel(ctx)

	return &GadgetContext{
		ctx:                      gCtx,
		cancel:                   cancel,
		id:                       id,
		runtime:                  runtime,
		runtimeParams:            runtimeParams,
		gadget:                   gadget,
		gadgetParams:             gadgetParams,
		args:                     args,
		parser:                   parser,
		logger:                   logger,
		operators:                operators.GetOperatorsForGadget(gadget),
		operatorsParamCollection: operatorsParamCollection,
		timeout:                  timeout,
		gadgetInfo:               gadgetInfo,

		dataSources: make(map[string]datasource.DataSource),
		vars:        make(map[string]any),
	}
}

func NewOCI(
	ctx context.Context,
	imageName string,
	options ...Option,
) *GadgetContext {
	gCtx, cancel := context.WithCancel(ctx)
	gadgetContext := &GadgetContext{
		ctx:    gCtx,
		cancel: cancel,
		args:   []string{},
		logger: logger.DefaultLogger(),

		imageName:   imageName,
		dataSources: make(map[string]datasource.DataSource),
		vars:        make(map[string]any),
		// dataOperators: operators.GetDataOperators(),
	}
	for _, option := range options {
		option(gadgetContext)
	}
	return gadgetContext
}

func (c *GadgetContext) ID() string {
	return c.id
}

func (c *GadgetContext) Context() context.Context {
	return c.ctx
}

func (c *GadgetContext) Cancel() {
	c.cancel()
}

func (c *GadgetContext) Parser() parser.Parser {
	return c.parser
}

func (c *GadgetContext) Runtime() runtime.Runtime {
	return c.runtime
}

func (c *GadgetContext) RuntimeParams() *params.Params {
	return c.runtimeParams
}

func (c *GadgetContext) GadgetDesc() gadgets.GadgetDesc {
	return c.gadget
}

func (c *GadgetContext) Operators() operators.Operators {
	return c.operators
}

func (c *GadgetContext) Logger() logger.Logger {
	return c.logger
}

func (c *GadgetContext) GadgetParams() *params.Params {
	return c.gadgetParams
}

func (c *GadgetContext) Args() []string {
	return c.args
}

func (c *GadgetContext) OperatorsParamCollection() params.Collection {
	return c.operatorsParamCollection
}

func (c *GadgetContext) Timeout() time.Duration {
	return c.timeout
}

func (c *GadgetContext) GadgetInfo() *runTypes.GadgetInfo {
	return c.gadgetInfo
}

func (c *GadgetContext) ImageName() string {
	return c.imageName
}

func (c *GadgetContext) DataOperators() []operators.DataOperator {
	return slices.Clone(c.dataOperators)
}

func (c *GadgetContext) RegisterDataSource(t datasource.Type, name string) (datasource.DataSource, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	ds := datasource.New(t, name)
	c.dataSources[name] = ds
	return ds, nil
}

func (c *GadgetContext) GetDataSources() map[string]datasource.DataSource {
	c.lock.Lock()
	defer c.lock.Unlock()
	return maps.Clone(c.dataSources)
}

func (c *GadgetContext) SetVar(varName string, value any) {
	c.vars[varName] = value
}

func (c *GadgetContext) GetVar(varName string) (any, bool) {
	res, ok := c.vars[varName]
	return res, ok
}

func (c *GadgetContext) GetVars() map[string]any {
	return maps.Clone(c.vars)
}

func (c *GadgetContext) Params() []*api.Param {
	return slices.Clone(c.params)
}

func (c *GadgetContext) SetParams(params []*api.Param) {
	for _, p := range params {
		c.params = append(c.params, p)
	}
}

func (c *GadgetContext) SetMetadata(m []byte) {
	c.metadata = m
}

func (c *GadgetContext) SerializeGadgetInfo() (*api.GadgetInfo, error) {
	gi := &api.GadgetInfo{
		Name:      "",
		ImageName: c.ImageName(),
		Metadata:  c.metadata,
		Params:    c.params,
	}

	for _, ds := range c.GetDataSources() {
		di := &api.DataSource{
			Id:          0,
			Name:        ds.Name(),
			Fields:      ds.Fields(),
			Tags:        ds.Tags(),
			Annotations: ds.Annotations(),
		}
		if ds.ByteOrder() == binary.BigEndian {
			di.Flags |= api.DataSourceFlagsBigEndian
		}
		gi.DataSources = append(gi.DataSources, di)
	}

	return gi, nil
}

func (c *GadgetContext) LoadGadgetInfo(info *api.GadgetInfo, paramValues api.ParamValues, run bool) error {
	c.lock.Lock()
	if c.loaded {
		// TODO: verify that info matches what we previously loaded
		c.lock.Unlock()
		return nil
	}

	c.dataSources = make(map[string]datasource.DataSource)
	for _, inds := range info.DataSources {
		ds, err := datasource.NewFromAPI(inds)
		if err != nil {
			c.lock.Unlock()
			return fmt.Errorf("creating DataSource from API: %w", err)
		}
		c.dataSources[inds.Name] = ds
	}
	c.params = info.Params
	c.loaded = true
	c.lock.Unlock()

	c.Logger().Debug("loaded gadget info")

	// After loading gadget info, start local operators as well
	localOperators, err := c.initAndPrepareOperators(paramValues)
	if err != nil {
		return fmt.Errorf("initializing local operators: %w", err)
	}

	if run {
		go c.run(localOperators)
	}

	return nil
}

func WithTimeoutOrCancel(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func WaitForTimeoutOrDone(c gadgets.GadgetContext) {
	ctx, cancel := WithTimeoutOrCancel(c.Context(), c.Timeout())
	defer cancel()
	<-ctx.Done()
}
