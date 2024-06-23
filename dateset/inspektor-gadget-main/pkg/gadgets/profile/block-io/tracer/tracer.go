// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/histogram"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type hist -type hist_key -cc clang -cflags ${CFLAGS} biolatency ./bpf/biolatency.bpf.c -- -I./bpf/

type Tracer struct {
	objs                biolatencyObjects
	blockRqCompleteLink link.Link
	blockRqInsertLink   link.Link
	blockRqIssueLink    link.Link
}

func NewTracer() (*Tracer, error) {
	t := &Tracer{}

	if err := t.install(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func getReport(histMap *ebpf.Map) (*types.Report, error) {
	key := biolatencyHistKey{}
	if err := histMap.NextKey(nil, unsafe.Pointer(&key)); err != nil {
		return nil, fmt.Errorf("getting next key: %w", err)
	}

	hist := biolatencyHist{}
	if err := histMap.Lookup(key, unsafe.Pointer(&hist)); err != nil {
		return nil, fmt.Errorf("getting histogram: %w", err)
	}

	return types.NewReport(histogram.UnitMicroseconds, hist.Slots[:]), nil
}

func (t *Tracer) Stop() (string, error) {
	defer t.close()

	result, err := t.collectResult()
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func (t *Tracer) collectResult() ([]byte, error) {
	if t.objs.Hists == nil {
		return nil, nil
	}
	report, err := getReport(t.objs.Hists)
	if err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

func (t *Tracer) close() {
	t.blockRqCompleteLink = gadgets.CloseLink(t.blockRqCompleteLink)
	t.blockRqInsertLink = gadgets.CloseLink(t.blockRqInsertLink)
	t.blockRqIssueLink = gadgets.CloseLink(t.blockRqIssueLink)

	t.objs.Close()
}

// Highly inspired from:
// https://github.com/iovisor/bcc/commit/952415e490bd#diff-2a74184cac5bad5399ebad3c47180658e27cca8070ddd28874017fbfdbb4690eR243
func getTracepointArguments(tracepoint string) ([]btf.FuncParam, error) {
	var typedef *btf.Typedef

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("loading kernel BTF information: %w", err)
	}

	if err := btfSpec.TypeByName(tracepoint, &typedef); err != nil {
		return nil, fmt.Errorf("searching %q: %w", tracepoint, err)
	}

	ptr, ok := typedef.Type.(*btf.Pointer)
	if !ok {
		return nil, fmt.Errorf("expecting btf.Pointer, got: %v", typedef.Type)
	}

	funcProto, ok := ptr.Target.(*btf.FuncProto)
	if !ok {
		return nil, fmt.Errorf("expecting btf.FuncProto, got: %v", ptr.Target)
	}

	return funcProto.Params, nil
}

func (t *Tracer) install() error {
	spec, err := loadBiolatency()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	insertArguments, err := getTracepointArguments("btf_trace_block_rq_insert")
	if err != nil {
		return fmt.Errorf("getting btf_trace_block_rq_insert number of arguments: %w", err)
	}

	issueArguments, err := getTracepointArguments("btf_trace_block_rq_issue")
	if err != nil {
		return fmt.Errorf("getting btf_trace_block_rq_issue number of arguments: %w", err)
	}

	consts := map[string]interface{}{
		// __DECLARE_TRACE always defines the ctx argument:
		// https://github.com/torvalds/linux/blob/39133352cbed6626956d38ed72012f49b0421e7b/include/linux/tracepoint.h#L434
		// And these tracepoint were modified to only have one argument in:
		// https://github.com/torvalds/linux/commit/a54895fa057c67700270777f7661d8d3c7fda88a#diff-034de3e50b949df539bb3602057e4e9d529f3e465881560df959078cd02202e0R75
		// So, we should test for two arguments, i.e. ctx and rq.
		"insert_arg_single": len(insertArguments) == 2,
		"issue_arg_single":  len(issueArguments) == 2,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("rewriting constants: %w", err)
	}

	if err := spec.LoadAndAssign(&t.objs, nil); err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	blockRqCompleteLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "block_rq_complete", Program: t.objs.IgProfioDone})
	if err != nil {
		return fmt.Errorf("attaching tracepoint for block_rq_complete: %w", err)
	}
	t.blockRqCompleteLink = blockRqCompleteLink

	blockRqInsertLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "block_rq_insert", Program: t.objs.IgProfioIns})
	if err != nil {
		return fmt.Errorf("attaching tracepoint for block_rq_insert: %w", err)
	}
	t.blockRqInsertLink = blockRqInsertLink

	blockRqIssueLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "block_rq_issue", Program: t.objs.IgProfioIss})
	if err != nil {
		return fmt.Errorf("attaching tracepoint for block_rq_issue: %w", err)
	}
	t.blockRqIssueLink = blockRqIssueLink

	return nil
}

// ---

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	t := &Tracer{}
	return t, nil
}

func (t *Tracer) RunWithResult(gadgetCtx gadgets.GadgetContext) ([]byte, error) {
	defer t.close()
	if err := t.install(); err != nil {
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return t.collectResult()
}
