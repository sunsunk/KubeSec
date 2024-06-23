// Copyright 2023-2024 The Inspektor Gadget authors
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

package api

import (
	"fmt"
	"net/url"
	"strings"
)

type (
	Params      []*Param
	ParamValues map[string]string
)

func ParseSocketAddress(addr string) (string, string, error) {
	socketURL, err := url.Parse(addr)
	if err != nil {
		return "", "", fmt.Errorf("invalid socket address %q: %w", addr, err)
	}
	var socketPath string
	socketType := socketURL.Scheme
	switch socketType {
	default:
		return "", "", fmt.Errorf("invalid type %q for socket; please use 'unix' or 'tcp'", socketType)
	case "unix":
		socketPath = socketURL.Path
	case "tcp":
		socketPath = socketURL.Host
	}
	return socketType, socketPath, nil
}

func (p *Param) AddPrefix(prefix string) *Param {
	p.Prefix = prefix + "." + p.Prefix
	return p
}

func (pv Params) AddPrefix(prefix string) Params {
	for _, p := range pv {
		p.AddPrefix(prefix)
	}
	return pv
}

func (pv ParamValues) ExtractPrefixedValues(prefix string) ParamValues {
	prefix = prefix + "."
	res := make(ParamValues)
	for k, v := range pv {
		if strings.HasPrefix(k, prefix) {
			res[strings.TrimPrefix(k, prefix)] = v
		}
	}
	return res
}
