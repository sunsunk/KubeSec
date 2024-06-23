/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	k8sframework "k8s.io/kubernetes/pkg/scheduler/framework"

	"volcano.sh/volcano/cmd/scheduler/app/options"
	"volcano.sh/volcano/pkg/scheduler/api"
)

const baselinePercentageOfNodesToFind = 50

var lastProcessedNodeIndex int

// CalculateNumOfFeasibleNodesToFind returns the number of feasible nodes that once found,
// the scheduler stops its search for more feasible nodes.
func CalculateNumOfFeasibleNodesToFind(numAllNodes int32) (numNodes int32) {
	opts := options.ServerOpts
	if numAllNodes <= opts.MinNodesToFind || opts.PercentageOfNodesToFind >= 100 {
		return numAllNodes
	}

	adaptivePercentage := opts.PercentageOfNodesToFind
	if adaptivePercentage <= 0 {
		adaptivePercentage = baselinePercentageOfNodesToFind - numAllNodes/125
		if adaptivePercentage < opts.MinPercentageOfNodesToFind {
			adaptivePercentage = opts.MinPercentageOfNodesToFind
		}
	}

	numNodes = numAllNodes * adaptivePercentage / 100
	if numNodes < opts.MinNodesToFind {
		numNodes = opts.MinNodesToFind
	}
	return numNodes
}

// PrioritizeNodes returns a map whose key is node's score and value are corresponding nodes
func PrioritizeNodes(task *api.TaskInfo, nodes []*api.NodeInfo, batchFn api.BatchNodeOrderFn, mapFn api.NodeOrderMapFn, reduceFn api.NodeOrderReduceFn) map[float64][]*api.NodeInfo {
	pluginNodeScoreMap := map[string]k8sframework.NodeScoreList{}
	nodeOrderScoreMap := map[string]float64{}
	nodeScores := map[float64][]*api.NodeInfo{}
	var workerLock sync.Mutex
	scoreNode := func(index int) {
		node := nodes[index]
		mapScores, orderScore, err := mapFn(task, node)
		if err != nil {
			klog.Errorf("Error in Calculating Priority for the node:%v", err)
			return
		}

		workerLock.Lock()
		for plugin, score := range mapScores {
			nodeScoreList, ok := pluginNodeScoreMap[plugin]
			if !ok {
				nodeScoreList = k8sframework.NodeScoreList{}
			}
			hp := k8sframework.NodeScore{}
			hp.Name = node.Name
			hp.Score = int64(math.Floor(score))
			pluginNodeScoreMap[plugin] = append(nodeScoreList, hp)
		}
		nodeOrderScoreMap[node.Name] = orderScore
		workerLock.Unlock()
	}
	workqueue.ParallelizeUntil(context.TODO(), 16, len(nodes), scoreNode)
	reduceScores, err := reduceFn(task, pluginNodeScoreMap)
	if err != nil {
		klog.Errorf("Error in Calculating Priority for the node:%v", err)
		return nodeScores
	}

	batchNodeScore, err := batchFn(task, nodes)
	if err != nil {
		klog.Errorf("Error in Calculating batch Priority for the node, err %v", err)
		return nodeScores
	}

	nodeScoreMap := map[string]float64{}
	for _, node := range nodes {
		// If no plugin is applied to this node, the default is 0.0
		score := 0.0
		if reduceScore, ok := reduceScores[node.Name]; ok {
			score += reduceScore
		}
		if orderScore, ok := nodeOrderScoreMap[node.Name]; ok {
			score += orderScore
		}
		if batchScore, ok := batchNodeScore[node.Name]; ok {
			score += batchScore
		}
		nodeScores[score] = append(nodeScores[score], node)

		if klog.V(5).Enabled() {
			nodeScoreMap[node.Name] = score
		}
	}

	klog.V(5).Infof("Prioritize nodeScoreMap for task<%s/%s> is: %v", task.Namespace, task.Name, nodeScoreMap)
	return nodeScores
}

// SortNodes returns nodes by order of score
func SortNodes(nodeScores map[float64][]*api.NodeInfo) []*api.NodeInfo {
	var nodesInorder []*api.NodeInfo
	var keys []float64
	for key := range nodeScores {
		keys = append(keys, key)
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(keys)))
	for _, key := range keys {
		nodes := nodeScores[key]
		nodesInorder = append(nodesInorder, nodes...)
	}
	return nodesInorder
}

// SelectBestNode returns best node whose score is highest, pick one randomly if there are many nodes with same score.
func SelectBestNode(nodeScores map[float64][]*api.NodeInfo) *api.NodeInfo {
	var bestNodes []*api.NodeInfo
	maxScore := -1.0
	for score, nodes := range nodeScores {
		if score > maxScore {
			maxScore = score
			bestNodes = nodes
		}
	}

	if len(bestNodes) == 0 {
		return nil
	}

	return bestNodes[rand.Intn(len(bestNodes))]
}

// GetNodeList returns values of the map 'nodes'
func GetNodeList(nodes map[string]*api.NodeInfo, nodeList []string) []*api.NodeInfo {
	result := make([]*api.NodeInfo, 0, len(nodeList))
	for _, nodename := range nodeList {
		if ni, ok := nodes[nodename]; ok {
			result = append(result, ni)
		}
	}
	return result
}

// ValidateVictims returns an error if the resources of the victims can't satisfy the preemptor
func ValidateVictims(preemptor *api.TaskInfo, node *api.NodeInfo, victims []*api.TaskInfo) error {
	// Victims should not be judged to be empty here.
	// It is possible to complete the scheduling of the preemptor without evicting the task.
	// In the first round, a large task (CPU: 8) is expelled, and a small task is scheduled (CPU: 2)
	// When the following rounds of victims are empty, it is still allowed to schedule small tasks (CPU: 2)
	futureIdle := node.FutureIdle()
	for _, victim := range victims {
		futureIdle.Add(victim.Resreq)
	}
	// Every resource of the preemptor needs to be less or equal than corresponding
	// idle resource after preemption.
	if !preemptor.InitResreq.LessEqual(futureIdle, api.Zero) {
		return fmt.Errorf("not enough resources: requested <%v>, but future idle <%v>",
			preemptor.InitResreq, futureIdle)
	}
	return nil
}

// GetMinInt return minimum int from vals
func GetMinInt(vals ...int) int {
	if len(vals) == 0 {
		return 0
	}

	min := vals[0]
	for _, val := range vals {
		if val <= min {
			min = val
		}
	}
	return min
}

// ConvertRes2ResList convert resource type from api.Resource in scheduler to v1.ResourceList in yaml
func ConvertRes2ResList(res *api.Resource) v1.ResourceList {
	var rl = v1.ResourceList{}
	rl[v1.ResourceCPU] = *resource.NewMilliQuantity(int64(res.MilliCPU), resource.DecimalSI)
	rl[v1.ResourceMemory] = *resource.NewQuantity(int64(res.Memory), resource.BinarySI)
	for resourceName, f := range res.ScalarResources {
		if resourceName == v1.ResourcePods {
			rl[resourceName] = *resource.NewQuantity(int64(f), resource.DecimalSI)
			continue
		}
		rl[resourceName] = *resource.NewMilliQuantity(int64(f), resource.DecimalSI)
	}
	return rl
}
