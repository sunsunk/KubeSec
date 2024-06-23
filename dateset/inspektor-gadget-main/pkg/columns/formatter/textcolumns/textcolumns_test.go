// Copyright 2022 The Inspektor Gadget authors
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

package textcolumns

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testStruct struct {
	Name     string  `column:"name,width:10"`
	Age      uint    `column:"age,width:4,align:right,fixed"`
	Size     float32 `column:"size,width:6,precision:2,align:right"`
	Balance  int     `column:"balance,width:8,align:right"`
	CanDance bool    `column:"canDance,width:8"`
}

var testEntries = []*testStruct{
	{"Alice", 32, 1.74, 1000, true},
	{"Bob", 26, 1.73, -200, true},
	{"Eve", 99, 5.12, 1000000, false},
	nil,
}

var testColumns = columns.MustCreateColumns[testStruct]().GetColumnMap()

func TestTextColumnsFormatter_FormatEntryAndTable(t *testing.T) {
	expected := []string{
		"Alice        32   1.74     1000 true    ",
		"Bob          26   1.73     -200 true    ",
		"Eve          99   5.12  1000000 false   ",
		"",
	}
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))

	t.Run("FormatEntry", func(t *testing.T) {
		for i, entry := range testEntries {
			assert.Equal(t, expected[i], formatter.FormatEntry(entry))
		}
	})

	t.Run("FormatTable", func(t *testing.T) {
		assert.Equal(t,
			strings.Join(append([]string{"NAME        AGE   SIZE  BALANCE CANDANCE", "————————————————————————————————————————"}, expected...), "\n"),
			formatter.FormatTable(testEntries),
		)
	})
}

func TestTextColumnsFormatter_FormatHeader(t *testing.T) {
	formatter := NewFormatter(testColumns)

	assert.Equal(t, "NAME        AGE   SIZE  BALANCE CANDANCE", formatter.FormatHeader())

	formatter.options.HeaderStyle = HeaderStyleLowercase
	assert.Equal(t, "name        age   size  balance candance", formatter.FormatHeader())

	formatter.options.HeaderStyle = HeaderStyleNormal
	assert.Equal(t, "name        age   size  balance canDance", formatter.FormatHeader())
}

func TestTextColumnsFormatter_FormatRowDivider(t *testing.T) {
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	assert.Equal(t, "————————————————————————————————————————", formatter.FormatRowDivider())
}

func TestTextColumnsFormatter_RecalculateWidths(t *testing.T) {
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	maxWidth := 100
	formatter.RecalculateWidths(maxWidth, true)
	assert.Equal(t, 100, len([]rune(formatter.FormatHeader())), "bad header width")
	assert.Equal(t, 100, len([]rune(formatter.FormatRowDivider())), "bad row divider width")

	for _, e := range testEntries {
		if e != nil {
			assert.Equal(t, 100, len([]rune(formatter.FormatEntry(e))), "bad entry width")
		}
	}
}

func TestTextColumnsFormatter_AdjustWidthsToContent(t *testing.T) {
	/*
		Expected result (32 characters):
		NAME   AGE SIZE BALANCE CANDANCE
		————————————————————————————————
		Alice   32 1.74    1000 true
		Bob     26 1.73    -200 true
		Eve     99 5.12 1000000 false
	*/
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	formatter.AdjustWidthsToContent(testEntries, true, 0, false)
	assert.Equal(t, "NAME   AGE SIZE BALANCE CANDANCE", formatter.FormatHeader(), "header does not match")
	assert.Equal(t, "————————————————————————————————", formatter.FormatRowDivider(), "row divider does not match")
	assert.Equal(t, "Alice   32 1.74    1000 true    ", formatter.FormatEntry(testEntries[0]), "entry does not match")
}

func TestTextColumnsFormatter_AdjustWidthsToContentNoHeaders(t *testing.T) {
	/*
		Expected result (29 characters):
		NAME   AGE SIZE BALANCE CAND…
		—————————————————————————————
		Alice   32 1.74    1000 true
		Bob     26 1.73    -200 true
		Eve     99 5.12 1000000 false
	*/
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	formatter.AdjustWidthsToContent(testEntries, false, 0, false)
	assert.Equal(t, "NAME   AGE SIZE BALANCE CAND…", formatter.FormatHeader(), "header does not match")
	assert.Equal(t, "—————————————————————————————", formatter.FormatRowDivider(), "row divider does not match")
	assert.Equal(t, "Alice   32 1.74    1000 true ", formatter.FormatEntry(testEntries[0]), "entry does not match")
}

func TestTextColumnsFormatter_AdjustWidthsMaxWidth(t *testing.T) {
	/*
		Expected result (9 characters):
		N… …  … …
		—————————
		A… …  … …
		B… …  … …
		E… …  … …
	*/
	formatter := NewFormatter(testColumns, WithRowDivider(DividerDash))
	formatter.AdjustWidthsToContent(testEntries, false, 9, true)
	assert.Equal(t, "N… …  … …", formatter.FormatHeader(), "header does not match")
	assert.Equal(t, "—————————", formatter.FormatRowDivider(), "row divider does not match")
	assert.Equal(t, "A… …  … …", formatter.FormatEntry(testEntries[0]), "entry does not match")
}

func TestWidthRestrictions(t *testing.T) {
	type testStruct struct {
		Name        string `column:"name,width:5,minWidth:2,maxWidth:10"`
		SecondField string `column:"second"`
	}
	entries := []*testStruct{
		{"123456789012", "123456789012"},
		{"234567890123", "234567890123"},
	}
	cols, err := columns.NewColumns[testStruct]()
	require.Nil(t, err, "error initializing: %s", err)

	formatter := NewFormatter(cols.GetColumnMap(), WithRowDivider(DividerDash), WithAutoScale(true))
	t.Run("maxWidth", func(t *testing.T) {
		formatter.RecalculateWidths(40, false)
		assert.Equal(t, "123456789… 123456789012", strings.TrimSpace(formatter.FormatEntry(entries[0])), "entry does not match")
	})
	t.Run("minWidth", func(t *testing.T) {
		formatter.RecalculateWidths(1, false)
		assert.Equal(t, "1… …", strings.TrimSpace(formatter.FormatEntry(entries[0])), "entry does not match")
	})
}

func TestWithTypeDefinition(t *testing.T) {
	type StringAlias string
	type testStruct struct {
		Name StringAlias `column:"name,width:5,minWidth:2,maxWidth:10"`
	}
	entries := []*testStruct{
		{"123456789012"},
		{"234567890123"},
	}
	cols, err := columns.NewColumns[testStruct]()
	require.Nil(t, err, "error initializing: %s", err)

	formatter := NewFormatter(cols.GetColumnMap(), WithAutoScale(false))
	formatter.AdjustWidthsToContent(entries, false, 0, false)
	for _, entry := range entries {
		assert.Equal(t, string(entry.Name), formatter.FormatEntry(entry))
	}
}

func TestTextColumnsFormatter_SetShownColumns(t *testing.T) {
	type test struct {
		name     string
		setShown []string
		expected []string
		err      bool
	}

	tests := []test{
		{
			name:     "default",
			setShown: nil,
			expected: []string{"name", "age", "size", "balance", "canDance"},
		},
		{
			name:     "empty",
			setShown: []string{},
			expected: []string{},
		},
		{
			name:     "shown-columns-match",
			setShown: []string{"name"},
			expected: []string{"name"},
		},
		{
			name:     "multipe-shown-columns-match",
			setShown: []string{"name", "canDance"},
			expected: []string{"name", "canDance"},
		},
		{
			name:     "column-not-found",
			setShown: []string{"foo"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			formatter := NewFormatter(testColumns)

			err := formatter.SetShowColumns(test.setShown)
			if test.err {
				require.NotNil(t, err, "SetShowColumns should have failed")
				return
			}

			require.Nil(t, err, "SetShowColumns failed: %s", err)

			found := []string{}
			for _, c := range formatter.showColumns {
				found = append(found, c.col.Name)
			}

			require.Equal(t, test.expected, found, "shown columns doesn't match the expected ones")
		})
	}
}

func TestDynamicFields(t *testing.T) {
	// Write the data in its binary representation to a buffer
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, []uint8("foobar"))
	require.NoError(t, err)
	err = binary.Write(buf, binary.LittleEndian, int32(1234567890))
	require.NoError(t, err)
	err = binary.Write(buf, binary.LittleEndian, true)
	require.NoError(t, err)

	fields := []columns.DynamicField{{
		Attributes: &columns.Attributes{
			Name:    "str",
			Width:   columns.GetDefault().DefaultWidth,
			Visible: true,
			Order:   0,
		},
		Type:   reflect.TypeOf([6]uint8{}),
		Offset: 0,
	}, {
		Attributes: &columns.Attributes{
			Name:    "int32",
			Width:   columns.GetDefault().DefaultWidth,
			Visible: true,
			Order:   1,
		},
		Type:   reflect.TypeOf(int32(0)),
		Offset: 6,
	}, {
		Attributes: &columns.Attributes{
			Name:    "bool",
			Width:   columns.GetDefault().DefaultWidth,
			Visible: true,
			Order:   2,
		},
		Type:   reflect.TypeOf(true),
		Offset: 10,
	}}

	type empty struct{}
	cols := columns.MustCreateColumns[empty]()
	cols.AddFields(fields, func(ev *empty) unsafe.Pointer {
		bytes := buf.Bytes()
		return unsafe.Pointer(&bytes[0])
	})
	formatter := NewFormatter[empty](cols.GetColumnMap())
	assert.Equal(t, "STR              INT32            BOOL            ", formatter.FormatHeader())
	assert.Equal(t, "foobar           1234567890       true            ", formatter.FormatEntry(&empty{}))
}
