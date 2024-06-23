package utils

import (
	"fmt"
	"github.com/hwameistor/hwameistor/pkg/local-disk-manager/member/types"
	corev1 "k8s.io/api/core/v1"
	"os"
	"reflect"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

// converts a raw key value pair string into a map of key value pairs
// example raw string of `foo="0" bar="1" baz="biz"` is returned as:
// map[string]string{"foo":"0", "bar":"1", "baz":"biz"}
func ParseKeyValuePairString(propsRaw string) map[string]string {
	// first split the single raw string on spaces and initialize a map of
	// a length equal to the number of pairs
	props := strings.Split(propsRaw, " ")
	propMap := make(map[string]string, len(props))

	for _, kvpRaw := range props {
		// split each individual key value pair on the equals sign
		kvp := strings.Split(kvpRaw, "=")
		if len(kvp) == 2 {
			// first element is the final key, second element is the final value
			// (don't forget to remove surrounding quotes from the value)
			propMap[kvp[0]] = strings.Replace(kvp[1], `"`, "", -1)
		}
	}

	return propMap
}

// GetNodeName gets the node name from env, else
// returns an error
func GetNodeName() string {
	nodeName, ok := os.LookupEnv("NODENAME")
	if !ok {
		log.Errorf("Failed to get NODENAME from ENV")
		return ""
	}

	return nodeName
}

// GetNamespace get Namespace from env, else it returns error
func GetNamespace() string {
	ns, ok := os.LookupEnv("NAMESPACE")
	if !ok {
		log.Errorf("Failed to get NameSpace from ENV")
		return ""
	}

	return ns
}

// ConvertNodeName e.g.(10.23.10.12 => 10-23-10-12)
func ConvertNodeName(node string) string {
	return strings.Replace(node, ".", "-", -1)
}

func FuncName() string {
	pc := make([]uintptr, 1)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	s := strings.Split(f.Name(), ".")
	return s[len(s)-1]
}

func StructToMap(in interface{}, tagName string) map[string]interface{} {
	out := make(map[string]interface{})

	v := reflect.ValueOf(in)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		log.WithError(fmt.Errorf("ToMap only accepts struct or struct pointer; got %T", v))
		return nil
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fi := t.Field(i)
		if tagValue := fi.Tag.Get(tagName); tagValue != "" {
			out[tagValue] = v.Field(i).Interface()
		}
	}
	return out
}

func StrFind(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

// FoundNewStringElems compare two arrays, find if there is new elem in new array
func FoundNewStringElems(old, new []string) ([]string, bool) {
	var om = make(map[string]bool)
	for _, s := range old {
		om[s] = true
	}
	var ns = make([]string, 0)
	for _, s := range new {
		if _, e := om[s]; !e {
			ns = append(ns, s)
		}
	}
	return ns, len(ns) > 0
}

// ByDiskSize makes an array of disks sortable by their size in descending
// order.
type ByDiskSize []types.Disk

func (a ByDiskSize) Less(i, j int) bool {
	return a[i].Capacity < a[j].Capacity
}
func (a ByDiskSize) Len() int      { return len(a) }
func (a ByDiskSize) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// ByVolumeCapacity makes an array of pvcs sortable by their storage capacity in descending
// order.
type ByVolumeCapacity []*corev1.PersistentVolumeClaim

func (a ByVolumeCapacity) Less(i, j int) bool {
	return a[i].Spec.Resources.Requests.Storage().Value() < a[j].Spec.Resources.Requests.Storage().Value()
}
func (a ByVolumeCapacity) Len() int      { return len(a) }
func (a ByVolumeCapacity) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
