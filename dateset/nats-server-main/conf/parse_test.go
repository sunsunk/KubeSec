package conf

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Test to make sure we get what we expect.

func test(t *testing.T, data string, ex map[string]any) {
	t.Helper()
	m, err := Parse(data)
	if err != nil {
		t.Fatalf("Received err: %v\n", err)
	}
	if m == nil {
		t.Fatal("Received nil map")
	}

	if !reflect.DeepEqual(m, ex) {
		t.Fatalf("Not Equal:\nReceived: '%+v'\nExpected: '%+v'\n", m, ex)
	}
}

func TestSimpleTopLevel(t *testing.T) {
	ex := map[string]any{
		"foo": "1",
		"bar": float64(2.2),
		"baz": true,
		"boo": int64(22),
	}
	test(t, "foo='1'; bar=2.2; baz=true; boo=22", ex)
}

func TestBools(t *testing.T) {
	ex := map[string]any{
		"foo": true,
	}
	test(t, "foo=true", ex)
	test(t, "foo=TRUE", ex)
	test(t, "foo=true", ex)
	test(t, "foo=yes", ex)
	test(t, "foo=on", ex)
}

var varSample = `
  index = 22
  foo = $index
`

func TestSimpleVariable(t *testing.T) {
	ex := map[string]any{
		"index": int64(22),
		"foo":   int64(22),
	}
	test(t, varSample, ex)
}

var varNestedSample = `
  index = 22
  nest {
    index = 11
    foo = $index
  }
  bar = $index
`

func TestNestedVariable(t *testing.T) {
	ex := map[string]any{
		"index": int64(22),
		"nest": map[string]any{
			"index": int64(11),
			"foo":   int64(11),
		},
		"bar": int64(22),
	}
	test(t, varNestedSample, ex)
}

func TestMissingVariable(t *testing.T) {
	_, err := Parse("foo=$index")
	if err == nil {
		t.Fatalf("Expected an error for a missing variable, got none")
	}
	if !strings.HasPrefix(err.Error(), "variable reference") {
		t.Fatalf("Wanted a variable reference err, got %q\n", err)
	}
}

func TestEnvVariable(t *testing.T) {
	ex := map[string]any{
		"foo": int64(22),
	}
	evar := "__UNIQ22__"
	os.Setenv(evar, "22")
	defer os.Unsetenv(evar)
	test(t, fmt.Sprintf("foo = $%s", evar), ex)
}

func TestEnvVariableString(t *testing.T) {
	ex := map[string]any{
		"foo": "xyz",
	}
	evar := "__UNIQ22__"
	os.Setenv(evar, "xyz")
	defer os.Unsetenv(evar)
	test(t, fmt.Sprintf("foo = $%s", evar), ex)
}

func TestEnvVariableStringStartingWithNumber(t *testing.T) {
	evar := "__UNIQ22__"
	os.Setenv(evar, "3xyz")
	defer os.Unsetenv(evar)

	_, err := Parse("foo = $%s")
	if err == nil {
		t.Fatalf("Expected err not being able to process string: %v\n", err)
	}
}

func TestEnvVariableStringStartingWithNumberAndSizeUnit(t *testing.T) {
	ex := map[string]any{
		"foo": "3Gyz",
	}
	evar := "__UNIQ22__"
	os.Setenv(evar, "3Gyz")
	defer os.Unsetenv(evar)
	test(t, fmt.Sprintf("foo = $%s", evar), ex)
}

func TestEnvVariableStringStartingWithNumberUsingQuotes(t *testing.T) {
	ex := map[string]any{
		"foo": "3xyz",
	}
	evar := "__UNIQ22__"
	os.Setenv(evar, "'3xyz'")
	defer os.Unsetenv(evar)
	test(t, fmt.Sprintf("foo = $%s", evar), ex)
}

func TestBcryptVariable(t *testing.T) {
	ex := map[string]any{
		"password": "$2a$11$ooo",
	}
	test(t, "password: $2a$11$ooo", ex)
}

var easynum = `
k = 8k
kb = 4kb
ki = 3ki
kib = 4ki
m = 1m
mb = 2MB
mi = 2Mi
mib = 64MiB
g = 2g
gb = 22GB
gi = 22Gi
gib = 22GiB
tb = 22TB
ti = 22Ti
tib = 22TiB
pb = 22PB
pi = 22Pi
pib = 22PiB
`

func TestConvenientNumbers(t *testing.T) {
	ex := map[string]any{
		"k":   int64(8 * 1000),
		"kb":  int64(4 * 1024),
		"ki":  int64(3 * 1024),
		"kib": int64(4 * 1024),
		"m":   int64(1000 * 1000),
		"mb":  int64(2 * 1024 * 1024),
		"mi":  int64(2 * 1024 * 1024),
		"mib": int64(64 * 1024 * 1024),
		"g":   int64(2 * 1000 * 1000 * 1000),
		"gb":  int64(22 * 1024 * 1024 * 1024),
		"gi":  int64(22 * 1024 * 1024 * 1024),
		"gib": int64(22 * 1024 * 1024 * 1024),
		"tb":  int64(22 * 1024 * 1024 * 1024 * 1024),
		"ti":  int64(22 * 1024 * 1024 * 1024 * 1024),
		"tib": int64(22 * 1024 * 1024 * 1024 * 1024),
		"pb":  int64(22 * 1024 * 1024 * 1024 * 1024 * 1024),
		"pi":  int64(22 * 1024 * 1024 * 1024 * 1024 * 1024),
		"pib": int64(22 * 1024 * 1024 * 1024 * 1024 * 1024),
	}
	test(t, easynum, ex)
}

var sample1 = `
foo  {
  host {
    ip   = '127.0.0.1'
    port = 4242
  }
  servers = [ "a.com", "b.com", "c.com"]
}
`

func TestSample1(t *testing.T) {
	ex := map[string]any{
		"foo": map[string]any{
			"host": map[string]any{
				"ip":   "127.0.0.1",
				"port": int64(4242),
			},
			"servers": []any{"a.com", "b.com", "c.com"},
		},
	}
	test(t, sample1, ex)
}

var cluster = `
cluster {
  port: 4244

  authorization {
    user: route_user
    password: top_secret
    timeout: 1
  }

  # Routes are actively solicited and connected to from this server.
  # Other servers can connect to us if they supply the correct credentials
  # in their routes definitions from above.

  // Test both styles of comments

  routes = [
    nats-route://foo:bar@apcera.me:4245
    nats-route://foo:bar@apcera.me:4246
  ]
}
`

func TestSample2(t *testing.T) {
	ex := map[string]any{
		"cluster": map[string]any{
			"port": int64(4244),
			"authorization": map[string]any{
				"user":     "route_user",
				"password": "top_secret",
				"timeout":  int64(1),
			},
			"routes": []any{
				"nats-route://foo:bar@apcera.me:4245",
				"nats-route://foo:bar@apcera.me:4246",
			},
		},
	}

	test(t, cluster, ex)
}

var sample3 = `
foo  {
  expr = '(true == "false")'
  text = 'This is a multi-line
text block.'
}
`

func TestSample3(t *testing.T) {
	ex := map[string]any{
		"foo": map[string]any{
			"expr": "(true == \"false\")",
			"text": "This is a multi-line\ntext block.",
		},
	}
	test(t, sample3, ex)
}

var sample4 = `
  array [
    { abc: 123 }
    { xyz: "word" }
  ]
`

func TestSample4(t *testing.T) {
	ex := map[string]any{
		"array": []any{
			map[string]any{"abc": int64(123)},
			map[string]any{"xyz": "word"},
		},
	}
	test(t, sample4, ex)
}

var sample5 = `
  now = 2016-05-04T18:53:41Z
  gmt = false

`

func TestSample5(t *testing.T) {
	dt, _ := time.Parse("2006-01-02T15:04:05Z", "2016-05-04T18:53:41Z")
	ex := map[string]any{
		"now": dt,
		"gmt": false,
	}
	test(t, sample5, ex)
}

func TestIncludes(t *testing.T) {
	ex := map[string]any{
		"listen": "127.0.0.1:4222",
		"authorization": map[string]any{
			"ALICE_PASS": "$2a$10$UHR6GhotWhpLsKtVP0/i6.Nh9.fuY73cWjLoJjb2sKT8KISBcUW5q",
			"BOB_PASS":   "$2a$11$dZM98SpGeI7dCFFGSpt.JObQcix8YHml4TBUZoge9R1uxnMIln5ly",
			"users": []any{
				map[string]any{
					"user":     "alice",
					"password": "$2a$10$UHR6GhotWhpLsKtVP0/i6.Nh9.fuY73cWjLoJjb2sKT8KISBcUW5q"},
				map[string]any{
					"user":     "bob",
					"password": "$2a$11$dZM98SpGeI7dCFFGSpt.JObQcix8YHml4TBUZoge9R1uxnMIln5ly"},
			},
			"timeout": float64(0.5),
		},
	}

	m, err := ParseFile("simple.conf")
	if err != nil {
		t.Fatalf("Received err: %v\n", err)
	}
	if m == nil {
		t.Fatal("Received nil map")
	}

	if !reflect.DeepEqual(m, ex) {
		t.Fatalf("Not Equal:\nReceived: '%+v'\nExpected: '%+v'\n", m, ex)
	}
}

var varIncludedVariablesSample = `
authorization {

  include "./includes/passwords.conf"

  CAROL_PASS: foo

  users = [
   {user: alice, password: $ALICE_PASS}
   {user: bob,   password: $BOB_PASS}
   {user: carol, password: $CAROL_PASS}
  ]
}
`

func TestIncludeVariablesWithChecks(t *testing.T) {
	p, err := parse(varIncludedVariablesSample, "", true)
	if err != nil {
		t.Fatalf("Received err: %v\n", err)
	}
	key := "authorization"
	m, ok := p.mapping[key]
	if !ok {
		t.Errorf("Expected %q to be in the config", key)
	}
	expectKeyVal := func(t *testing.T, m any, expectedKey string, expectedVal string, expectedLine, expectedPos int) {
		t.Helper()
		tk := m.(*token)
		v := tk.Value()
		vv := v.(map[string]any)
		value, ok := vv[expectedKey]
		if !ok {
			t.Errorf("Expected key %q", expectedKey)
		}
		tk, ok = value.(*token)
		if !ok {
			t.Fatalf("Expected token %v", value)
		}
		if tk.Line() != expectedLine {
			t.Errorf("Expected token to be at line %d, got: %d", expectedLine, tk.Line())
		}
		if tk.Position() != expectedPos {
			t.Errorf("Expected token to be at position %d, got: %d", expectedPos, tk.Position())
		}
		v = tk.Value()
		if v != expectedVal {
			t.Errorf("Expected %q, got: %s", expectedVal, v)
		}
	}
	expectKeyVal(t, m, "ALICE_PASS", "$2a$10$UHR6GhotWhpLsKtVP0/i6.Nh9.fuY73cWjLoJjb2sKT8KISBcUW5q", 2, 1)
	expectKeyVal(t, m, "BOB_PASS", "$2a$11$dZM98SpGeI7dCFFGSpt.JObQcix8YHml4TBUZoge9R1uxnMIln5ly", 3, 1)
	expectKeyVal(t, m, "CAROL_PASS", "foo", 6, 3)
}

func TestParserNoInfiniteLoop(t *testing.T) {
	for _, test := range []string{`A@@Føøøø?˛ø:{øøøø˙˙`, `include "9/�`} {
		if _, err := Parse(test); err == nil {
			t.Fatal("expected an error")
		} else if !strings.Contains(err.Error(), "Unexpected EOF") {
			t.Fatal("expected unexpected eof error")
		}
	}
}

func TestParseWithNoValuesAreInvalid(t *testing.T) {
	for _, test := range []struct {
		name string
		conf string
		err  string
	}{
		{
			"invalid key without values",
			`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
			"config is invalid (:1:41)",
		},
		{
			"invalid untrimmed key without values",
			`              aaaaaaaaaaaaaaaaaaaaaaaaaaa`,
			"config is invalid (:1:41)",
		},
		{
			"invalid untrimmed key without values",
			`     aaaaaaaaaaaaaaaaaaaaaaaaaaa         `,
			"config is invalid (:1:41)",
		},
		{
			"invalid keys after comments",
			`
          		# with comments and no spaces to create key values
         		# is also an invalid config.
         		aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                        `,
			"config is invalid (:5:25)",
		},
		{
			"comma separated without values are invalid",
			`
                        a,a,a,a,a,a,a,a,a,a,a
                        `,
			"config is invalid (:3:25)",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parse(test.conf, "", true); err == nil {
				t.Error("expected an error")
			} else if !strings.Contains(err.Error(), test.err) {
				t.Errorf("expected invalid conf error, got: %v", err)
			}
		})
	}
}

func TestParseWithNoValuesEmptyConfigsAreValid(t *testing.T) {
	for _, test := range []struct {
		name string
		conf string
	}{
		{
			"empty conf",
			"",
		},
		{
			"empty conf with line breaks",
			`


                        `,
		},
		{
			"just comments with no values",
			`
                        # just comments with no values
                        # is still valid.
                        `,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parse(test.conf, "", true); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseWithTrailingBracketsAreValid(t *testing.T) {
	for _, test := range []struct {
		name string
		conf string
	}{
		{
			"empty conf",
			"{}",
		},
		{
			"just comments with no values",
			`
                        {
                        # comments in the body
                        }
                        `,
		},
		{
			// trailing brackets accidentally can become keys,
			// this is valid since needed to support JSON like configs..
			"trailing brackets after config",
			`
                        accounts { users = [{}]}
                        }
                        `,
		},
		{
			"wrapped in brackets",
			`{
                          accounts { users = [{}]}
                        }
                        `,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parse(test.conf, "", true); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseWithNoValuesIncludes(t *testing.T) {
	for _, test := range []struct {
		input    string
		includes map[string]string
		err      string
		linepos  string
	}{
		{
			`# includes
			accounts {
                          foo { include 'foo.conf'}
                          bar { users = [{user = "bar"}] }
                          quux { include 'quux.conf'}
                        }
                        `,
			map[string]string{
				"foo.conf":  ``,
				"quux.conf": `?????????????`,
			},
			"error parsing include file 'quux.conf', config is invalid",
			"quux.conf:1:1",
		},
		{
			`# includes
			accounts {
                          foo { include 'foo.conf'}
                          bar { include 'bar.conf'}
                          quux { include 'quux.conf'}
                        }
                        `,
			map[string]string{
				"foo.conf": ``, // Empty configs are ok
				"bar.conf": `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
				"quux.conf": `
                                   # just some comments,
                                   # and no key values also ok.
                                `,
			},
			"error parsing include file 'bar.conf', config is invalid",
			"bar.conf:1:34",
		},
	} {
		t.Run("", func(t *testing.T) {
			sdir := t.TempDir()
			f, err := os.CreateTemp(sdir, "nats.conf-")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.Name(), []byte(test.input), 066); err != nil {
				t.Error(err)
			}
			if test.includes != nil {
				for includeFile, contents := range test.includes {
					inf, err := os.Create(filepath.Join(sdir, includeFile))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(inf.Name(), []byte(contents), 066); err != nil {
						t.Error(err)
					}
				}
			}
			if _, err := parse(test.input, f.Name(), true); err == nil {
				t.Error("expected an error")
			} else if !strings.Contains(err.Error(), test.err) || !strings.Contains(err.Error(), test.linepos) {
				t.Errorf("expected invalid conf error, got: %v", err)
			}
		})
	}
}

func TestJSONParseCompat(t *testing.T) {
	for _, test := range []struct {
		name     string
		input    string
		includes map[string]string
		expected map[string]any
	}{
		{
			"JSON with nested blocks",
			`
                        {
                          "http_port": 8227,
                          "port": 4227,
                          "write_deadline": "1h",
                          "cluster": {
                            "port": 6222,
                            "routes": [
                              "nats://127.0.0.1:4222",
                              "nats://127.0.0.1:4223",
                              "nats://127.0.0.1:4224"
                            ]
                          }
                        }
                        `,
			nil,
			map[string]any{
				"http_port":      int64(8227),
				"port":           int64(4227),
				"write_deadline": "1h",
				"cluster": map[string]any{
					"port": int64(6222),
					"routes": []any{
						"nats://127.0.0.1:4222",
						"nats://127.0.0.1:4223",
						"nats://127.0.0.1:4224",
					},
				},
			},
		},
		{
			"JSON with nested blocks",
			`{
                          "jetstream": {
                            "store_dir": "/tmp/nats"
                            "max_mem": 1000000,
                          },
                          "port": 4222,
                          "server_name": "nats1"
                        }
                        `,
			nil,
			map[string]any{
				"jetstream": map[string]any{
					"store_dir": "/tmp/nats",
					"max_mem":   int64(1_000_000),
				},
				"port":        int64(4222),
				"server_name": "nats1",
			},
		},
		{
			"JSON empty object in one line",
			`{}`,
			nil,
			map[string]any{},
		},
		{
			"JSON empty object with line breaks",
			`
                        {
                        }
                        `,
			nil,
			map[string]any{},
		},
		{
			"JSON includes",
			`
                        accounts {
                          foo  { include 'foo.json'  }
                          bar  { include 'bar.json'  }
                          quux { include 'quux.json' }
                        }
                        `,
			map[string]string{
				"foo.json": `{ "users": [ {"user": "foo"} ] }`,
				"bar.json": `{
                                  "users": [ {"user": "bar"} ]
                                }`,
				"quux.json": `{}`,
			},
			map[string]any{
				"accounts": map[string]any{
					"foo": map[string]any{
						"users": []any{
							map[string]any{
								"user": "foo",
							},
						},
					},
					"bar": map[string]any{
						"users": []any{
							map[string]any{
								"user": "bar",
							},
						},
					},
					"quux": map[string]any{},
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sdir := t.TempDir()
			f, err := os.CreateTemp(sdir, "nats.conf-")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.Name(), []byte(test.input), 066); err != nil {
				t.Error(err)
			}
			if test.includes != nil {
				for includeFile, contents := range test.includes {
					inf, err := os.Create(filepath.Join(sdir, includeFile))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(inf.Name(), []byte(contents), 066); err != nil {
						t.Error(err)
					}
				}
			}
			m, err := ParseFile(f.Name())
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !reflect.DeepEqual(m, test.expected) {
				t.Fatalf("Not Equal:\nReceived: '%+v'\nExpected: '%+v'\n", m, test.expected)
			}
		})
	}
}
