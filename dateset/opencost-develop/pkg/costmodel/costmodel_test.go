package costmodel

import (
	"testing"

	"github.com/opencost/opencost/core/pkg/util"
)

func Test_CostData_GetController_CronJob(t *testing.T) {
	cases := []struct {
		name string
		cd   CostData

		expectedName          string
		expectedKind          string
		expectedHasController bool
	}{
		{
			name: "batch/v1beta1 CronJob Job name",
			cd: CostData{
				// batch/v1beta1 CronJobs create Jobs with a 10 character
				// timestamp appended to the end of the name.
				//
				// It looks like this:
				// CronJob: cronjob-1
				// Job: cronjob-1-1651057200
				// Pod: cronjob-1-1651057200-mf5c9
				Jobs: []string{"cronjob-1-1651057200"},
			},

			expectedName:          "cronjob-1",
			expectedKind:          "job",
			expectedHasController: true,
		},
		{
			name: "batch/v1 CronJob Job name",
			cd: CostData{
				// batch/v1CronJobs create Jobs with an 8 character timestamp
				// appended to the end of the name.
				//
				// It looks like this:
				// CronJob: cj-v1
				// Job: cj-v1-27517770
				// Pod: cj-v1-27517770-xkrgn
				Jobs: []string{"cj-v1-27517770"},
			},

			expectedName:          "cj-v1",
			expectedKind:          "job",
			expectedHasController: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, kind, hasController := c.cd.GetController()

			if name != c.expectedName {
				t.Errorf("Name mismatch. Expected: %s. Got: %s", c.expectedName, name)
			}
			if kind != c.expectedKind {
				t.Errorf("Kind mismatch. Expected: %s. Got: %s", c.expectedKind, kind)
			}
			if hasController != c.expectedHasController {
				t.Errorf("HasController mismatch. Expected: %t. Got: %t", c.expectedHasController, hasController)
			}
		})
	}
}

func Test_getContainerAllocation(t *testing.T) {
	cases := []struct {
		name string
		cd   CostData

		expectedCPUAllocation []*util.Vector
		expectedRAMAllocation []*util.Vector
	}{
		{
			name: "Requests greater than usage",
			cd: CostData{
				CPUReq:  []*util.Vector{{Value: 1.0, Timestamp: 1686929350}},
				CPUUsed: []*util.Vector{{Value: .01, Timestamp: 1686929350}},
				RAMReq:  []*util.Vector{{Value: 10000000, Timestamp: 1686929350}},
				RAMUsed: []*util.Vector{{Value: 5500000, Timestamp: 1686929350}},
			},

			expectedCPUAllocation: []*util.Vector{{Value: 1.0, Timestamp: 1686929350}},
			expectedRAMAllocation: []*util.Vector{{Value: 10000000, Timestamp: 1686929350}},
		},
		{
			name: "Requests less than usage",
			cd: CostData{
				CPUReq:  []*util.Vector{{Value: 1.0, Timestamp: 1686929350}},
				CPUUsed: []*util.Vector{{Value: 2.2, Timestamp: 1686929350}},
				RAMReq:  []*util.Vector{{Value: 10000000, Timestamp: 1686929350}},
				RAMUsed: []*util.Vector{{Value: 75000000, Timestamp: 1686929350}},
			},

			expectedCPUAllocation: []*util.Vector{{Value: 2.2, Timestamp: 1686929350}},
			expectedRAMAllocation: []*util.Vector{{Value: 75000000, Timestamp: 1686929350}},
		},
		{
			// Expected behavior for getContainerAllocation is to always use the
			// highest Timestamp value. The significance of 10 seconds comes
			// from the current default in ApplyVectorOp() in
			// pkg/util/vector.go.
			name: "Mismatched timestamps less than 10 seconds apart",
			cd: CostData{
				CPUReq:  []*util.Vector{{Value: 1.0, Timestamp: 1686929354}},
				CPUUsed: []*util.Vector{{Value: .01, Timestamp: 1686929350}},
				RAMReq:  []*util.Vector{{Value: 10000000, Timestamp: 1686929354}},
				RAMUsed: []*util.Vector{{Value: 5500000, Timestamp: 1686929350}},
			},

			expectedCPUAllocation: []*util.Vector{{Value: 1.0, Timestamp: 1686929354}},
			expectedRAMAllocation: []*util.Vector{{Value: 10000000, Timestamp: 1686929354}},
		},
		{
			// Expected behavior for getContainerAllocation is to always use the
			// hightest Timestamp value. The significance of 10 seconds comes
			// from the current default in ApplyVectorOp() in
			// pkg/util/vector.go.
			name: "Mismatched timestamps greater than 10 seconds apart",
			cd: CostData{
				CPUReq:  []*util.Vector{{Value: 1.0, Timestamp: 1686929399}},
				CPUUsed: []*util.Vector{{Value: .01, Timestamp: 1686929350}},
				RAMReq:  []*util.Vector{{Value: 10000000, Timestamp: 1686929399}},
				RAMUsed: []*util.Vector{{Value: 5500000, Timestamp: 1686929350}},
			},

			expectedCPUAllocation: []*util.Vector{{Value: 1.0, Timestamp: 1686929399}},
			expectedRAMAllocation: []*util.Vector{{Value: 10000000, Timestamp: 1686929399}},
		},
		{
			name: "Requests has no values",
			cd: CostData{
				CPUReq:  []*util.Vector{{Value: 0, Timestamp: 0}},
				CPUUsed: []*util.Vector{{Value: .01, Timestamp: 1686929350}},
				RAMReq:  []*util.Vector{{Value: 0, Timestamp: 0}},
				RAMUsed: []*util.Vector{{Value: 5500000, Timestamp: 1686929350}},
			},

			expectedCPUAllocation: []*util.Vector{{Value: .01, Timestamp: 1686929350}},
			expectedRAMAllocation: []*util.Vector{{Value: 5500000, Timestamp: 1686929350}},
		},
		{
			name: "Usage has no values",
			cd: CostData{
				CPUReq:  []*util.Vector{{Value: 1.0, Timestamp: 1686929350}},
				CPUUsed: []*util.Vector{{Value: 0, Timestamp: 0}},
				RAMReq:  []*util.Vector{{Value: 10000000, Timestamp: 1686929350}},
				RAMUsed: []*util.Vector{{Value: 0, Timestamp: 0}},
			},

			expectedCPUAllocation: []*util.Vector{{Value: 1.0, Timestamp: 1686929350}},
			expectedRAMAllocation: []*util.Vector{{Value: 10000000, Timestamp: 1686929350}},
		},
		{
			// WRN Log should be thrown
			name: "Both have no values",
			cd: CostData{
				CPUReq:  []*util.Vector{{Value: 0, Timestamp: 0}},
				CPUUsed: []*util.Vector{{Value: 0, Timestamp: 0}},
				RAMReq:  []*util.Vector{{Value: 0, Timestamp: 0}},
				RAMUsed: []*util.Vector{{Value: 0, Timestamp: 0}},
			},

			expectedCPUAllocation: []*util.Vector{{Value: 0, Timestamp: 0}},
			expectedRAMAllocation: []*util.Vector{{Value: 0, Timestamp: 0}},
		},
		{
			name: "Requests is Nil",
			cd: CostData{
				CPUReq:  []*util.Vector{nil},
				CPUUsed: []*util.Vector{{Value: .01, Timestamp: 1686929350}},
				RAMReq:  []*util.Vector{nil},
				RAMUsed: []*util.Vector{{Value: 5500000, Timestamp: 1686929350}},
			},

			expectedCPUAllocation: []*util.Vector{{Value: .01, Timestamp: 1686929350}},
			expectedRAMAllocation: []*util.Vector{{Value: 5500000, Timestamp: 1686929350}},
		},
		{
			name: "Usage is nil",
			cd: CostData{
				CPUReq:  []*util.Vector{{Value: 1.0, Timestamp: 1686929350}},
				CPUUsed: []*util.Vector{nil},
				RAMReq:  []*util.Vector{{Value: 10000000, Timestamp: 1686929350}},
				RAMUsed: []*util.Vector{nil},
			},

			expectedCPUAllocation: []*util.Vector{{Value: 1.0, Timestamp: 1686929350}},
			expectedRAMAllocation: []*util.Vector{{Value: 10000000, Timestamp: 1686929350}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cpuAllocation := getContainerAllocation(c.cd.CPUReq[0], c.cd.CPUUsed[0], "CPU")
			ramAllocation := getContainerAllocation(c.cd.RAMReq[0], c.cd.RAMUsed[0], "RAM")

			if cpuAllocation[0].Value != c.expectedCPUAllocation[0].Value {
				t.Errorf("CPU Allocation mismatch. Expected Value: %f. Got: %f", cpuAllocation[0].Value, c.expectedCPUAllocation[0].Value)
			}
			if cpuAllocation[0].Timestamp != c.expectedCPUAllocation[0].Timestamp {
				t.Errorf("CPU Allocation mismatch. Expected Timestamp: %f. Got: %f", cpuAllocation[0].Timestamp, c.expectedCPUAllocation[0].Timestamp)
			}
			if ramAllocation[0].Value != c.expectedRAMAllocation[0].Value {
				t.Errorf("RAM Allocation mismatch. Expected Value: %f. Got: %f", ramAllocation[0].Value, c.expectedRAMAllocation[0].Value)
			}
			if ramAllocation[0].Timestamp != c.expectedRAMAllocation[0].Timestamp {
				t.Errorf("RAM Allocation mismatch. Expected Timestamp: %f. Got: %f", ramAllocation[0].Timestamp, c.expectedRAMAllocation[0].Timestamp)
			}
		})
	}
}
