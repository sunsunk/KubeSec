// Copyright 2023 The Inspektor Gadget authors
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

package json

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

type testStruct struct {
	Name     string  `column:"name"`
	Age      uint    `column:"age"`
	Size     float32 `column:"size"`
	Balance  int     `column:"balance"`
	CanDance bool    `column:"canDance"`
}

var testEntries = []*testStruct{
	{"Alice", 32, 1.74, 1000, true},
	{"Bob", 26, 1.73, -200, true},
	{"Eve", 99, 5.12, 1000000, false},
	nil,
}

var testColumns = columns.MustCreateColumns[testStruct]().GetColumnMap()

func TestJSONFormatter_FormatEntry(t *testing.T) {
	expected := []string{
		`{"name": "Alice", "age": 32, "size": 1.74, "balance": 1000, "canDance": true}`,
		`{"name": "Bob", "age": 26, "size": 1.73, "balance": -200, "canDance": true}`,
		`{"name": "Eve", "age": 99, "size": 5.12, "balance": 1000000, "canDance": false}`,
		`null`,
	}
	formatter := NewFormatter(testColumns)
	for i, entry := range testEntries {
		assert.Equal(t, expected[i], formatter.FormatEntry(entry))
	}
}

func TestJSONFormatter_PrettyFormatEntry(t *testing.T) {
	expected := []string{
		`{
  "name": "Alice",
  "age": 32,
  "size": 1.74,
  "balance": 1000,
  "canDance": true
}`,
		`{
  "name": "Bob",
  "age": 26,
  "size": 1.73,
  "balance": -200,
  "canDance": true
}`,
		`{
  "name": "Eve",
  "age": 99,
  "size": 5.12,
  "balance": 1000000,
  "canDance": false
}`,
		`null`,
	}
	formatter := NewFormatter(testColumns, WithPrettyPrint())
	for i, entry := range testEntries {
		assert.Equal(t, expected[i], formatter.FormatEntry(entry))
	}
}

func TestJSONFormatter_FormatEntries(t *testing.T) {
	type testCase struct {
		entries  []*testStruct
		expected string
	}

	tests := map[string]testCase{
		"nil": {
			entries:  nil,
			expected: "null",
		},
		"empty": {
			entries:  []*testStruct{},
			expected: "[]",
		},
		"multiple": {
			entries:  testEntries,
			expected: `[{"name": "Alice", "age": 32, "size": 1.74, "balance": 1000, "canDance": true}, {"name": "Bob", "age": 26, "size": 1.73, "balance": -200, "canDance": true}, {"name": "Eve", "age": 99, "size": 5.12, "balance": 1000000, "canDance": false}, null]`,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			formatter := NewFormatter(testColumns)
			assert.Equal(t, test.expected, formatter.FormatEntries(test.entries))
		})
	}
}

func TestJSONFormatter_PrettyFormatEntries(t *testing.T) {
	expected := `[
  {
    "name": "Alice",
    "age": 32,
    "size": 1.74,
    "balance": 1000,
    "canDance": true
  },
  {
    "name": "Bob",
    "age": 26,
    "size": 1.73,
    "balance": -200,
    "canDance": true
  },
  {
    "name": "Eve",
    "age": 99,
    "size": 5.12,
    "balance": 1000000,
    "canDance": false
  },
  null
]`

	formatter := NewFormatter(testColumns, WithPrettyPrint())
	assert.Equal(t, expected, formatter.FormatEntries(testEntries))
}

func BenchmarkFormatter(b *testing.B) {
	b.StopTimer()
	formatter := NewFormatter(testColumns)
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		formatter.FormatEntry(testEntries[n%len(testEntries)])
	}
}

func BenchmarkNative(b *testing.B) {
	b.StopTimer()
	// do a dry-run to enable caching
	json.Marshal(testEntries[0])
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		json.Marshal(testEntries[n%len(testEntries)])
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
	assert.Equal(t, `{"str": "foobar", "int32": 1234567890, "bool": true}`, formatter.FormatEntry(&empty{}))
}

func TestJSONFormatter(t *testing.T) {
	type testStruct struct{}

	cols := columns.MustCreateColumns[testStruct]()

	require.NoError(t, cols.AddColumn(columns.Attributes{
		Name: "parent.child1.grandchild1",
	}, func(t *testStruct) any { return "parent.child1.grandchild1_text" }))
	require.NoError(t, cols.AddColumn(columns.Attributes{
		Name: "parent.child1.grandchild2",
	}, func(t *testStruct) any { return "parent.child1.grandchild2_text" }))
	require.NoError(t, cols.AddColumn(columns.Attributes{
		Name: "parent.child2.grandchild1",
	}, func(t *testStruct) any { return "parent.child2.grandchild1_text" }))
	require.NoError(t, cols.AddColumn(columns.Attributes{
		Name: "parent.child3",
	}, func(t *testStruct) any { return "parent.child3_text" }))
	require.NoError(t, cols.AddColumn(columns.Attributes{
		Name: "parent.child4",
	}, func(t *testStruct) any { return 42444 }))

	require.NoError(t, cols.AddColumn(columns.Attributes{
		Name: "parent.child1",
	}, func(t *testStruct) any { return "This should be skipped/filtered" }))

	expected := `{
  "parent": {
    "child1": {
      "grandchild1": "parent.child1.grandchild1_text",
      "grandchild2": "parent.child1.grandchild2_text"
    },
    "child2": {
      "grandchild1": "parent.child2.grandchild1_text"
    },
    "child3": "parent.child3_text",
    "child4": 42444
  }
}`

	formatter := NewFormatter[testStruct](cols.ColumnMap)
	actual := formatter.FormatEntry(&testStruct{})
	assert.JSONEq(t, expected, actual)

	prettyFormatter := NewFormatter[testStruct](cols.ColumnMap, WithPrettyPrint())
	actual = prettyFormatter.FormatEntry(&testStruct{})
	// We don't know the ordering of the children inside the parent
	// So we need to compare the JSON objects instead of the strings
	assert.JSONEq(t, expected, actual)
}

func TestJSONFormatterDeeplyNested(t *testing.T) {
	type testStruct struct{}

	cols := columns.MustCreateColumns[testStruct]()

	require.NoError(t, cols.AddColumn(columns.Attributes{
		Name: "a.b.c.d.e.f.g",
	}, func(t *testStruct) any { return "foobar" }))

	expected := `{
  "a": {
    "b": {
      "c": {
        "d": {
          "e": {
            "f": {
              "g": "foobar"
            }
          }
        }
      }
    }
  }
}`

	formatter := NewFormatter[testStruct](cols.ColumnMap)
	actual := formatter.FormatEntry(&testStruct{})
	assert.JSONEq(t, expected, actual)

	prettyFormatter := NewFormatter[testStruct](cols.ColumnMap, WithPrettyPrint())
	actual = prettyFormatter.FormatEntry(&testStruct{})
	assert.Equal(t, expected, actual)
}
