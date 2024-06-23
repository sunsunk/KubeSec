package predicates

import (
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/spf13/pflag"

	apiv1 "k8s.io/api/core/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	schedulingv1beta1 "volcano.sh/apis/pkg/apis/scheduling/v1beta1"
	"volcano.sh/volcano/cmd/scheduler/app/options"
	"volcano.sh/volcano/pkg/kube"
	"volcano.sh/volcano/pkg/scheduler/actions/allocate"
	"volcano.sh/volcano/pkg/scheduler/api"
	"volcano.sh/volcano/pkg/scheduler/cache"
	"volcano.sh/volcano/pkg/scheduler/conf"
	"volcano.sh/volcano/pkg/scheduler/framework"
	"volcano.sh/volcano/pkg/scheduler/plugins/gang"
	"volcano.sh/volcano/pkg/scheduler/plugins/priority"
	"volcano.sh/volcano/pkg/scheduler/util"
)

func getWorkerAffinity() *apiv1.Affinity {
	return &apiv1.Affinity{
		PodAntiAffinity: &apiv1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []apiv1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "role",
								Operator: "In",
								Values:   []string{"worker"},
							},
						},
					},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		},
	}
}

func TestEventHandler(t *testing.T) {
	var tmp *cache.SchedulerCache
	patches := gomonkey.ApplyMethod(reflect.TypeOf(tmp), "AddBindTask", func(scCache *cache.SchedulerCache, task *api.TaskInfo) error {
		scCache.Binder.Bind(nil, []*api.TaskInfo{task})
		return nil
	})
	defer patches.Reset()

	framework.RegisterPluginBuilder(PluginName, New)
	framework.RegisterPluginBuilder(gang.PluginName, gang.New)
	framework.RegisterPluginBuilder(priority.PluginName, priority.New)
	options.ServerOpts = options.NewServerOption()
	defer framework.CleanupPluginBuilders()

	option := options.NewServerOption()
	option.AddFlags(pflag.CommandLine)
	option.RegisterOptions()

	config, err := kube.BuildConfig(option.KubeClientOptions)
	if err != nil {
		return
	}

	sc := cache.New(config, option.SchedulerNames, option.DefaultQueue, option.NodeSelector, option.NodeWorkerThreads, nil)
	schedulerCache := sc.(*cache.SchedulerCache)

	// pending pods
	w1 := util.BuildPod("ns1", "worker-1", "", apiv1.PodPending, api.BuildResourceList("3", "3k"), "pg1", map[string]string{"role": "worker"}, map[string]string{"selector": "worker"})
	w2 := util.BuildPod("ns1", "worker-2", "", apiv1.PodPending, api.BuildResourceList("5", "5k"), "pg1", map[string]string{"role": "worker"}, map[string]string{})
	w3 := util.BuildPod("ns1", "worker-3", "", apiv1.PodPending, api.BuildResourceList("4", "4k"), "pg2", map[string]string{"role": "worker"}, map[string]string{})
	w1.Spec.Affinity = getWorkerAffinity()
	w2.Spec.Affinity = getWorkerAffinity()
	w3.Spec.Affinity = getWorkerAffinity()

	// nodes
	n1 := util.BuildNode("node1", api.BuildResourceList("4", "4k", []api.ScalarResource{{Name: "pods", Value: "10"}}...), map[string]string{"selector": "worker"})
	n2 := util.BuildNode("node2", api.BuildResourceList("3", "3k", []api.ScalarResource{{Name: "pods", Value: "10"}}...), map[string]string{})
	n1.Status.Allocatable["pods"] = resource.MustParse("15")
	n2.Status.Allocatable["pods"] = resource.MustParse("15")
	n1.Labels["kubernetes.io/hostname"] = "node1"
	n2.Labels["kubernetes.io/hostname"] = "node2"

	// priority
	p1 := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "p1"}, Value: 1}
	p2 := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "p2"}, Value: 2}
	// podgroup
	pg1 := &schedulingv1beta1.PodGroup{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns1",
			Name:      "pg1",
		},
		Spec: schedulingv1beta1.PodGroupSpec{
			Queue:             "q1",
			MinMember:         int32(2),
			PriorityClassName: p2.Name,
		},
	}
	pg2 := &schedulingv1beta1.PodGroup{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns1",
			Name:      "pg2",
		},
		Spec: schedulingv1beta1.PodGroupSpec{
			Queue:             "q1",
			MinMember:         int32(1),
			PriorityClassName: p1.Name,
		},
	}
	// queue
	queue1 := &schedulingv1beta1.Queue{
		ObjectMeta: metav1.ObjectMeta{
			Name: "q1",
		},
	}

	// tests
	tests := []struct {
		name     string
		pods     []*apiv1.Pod
		nodes    []*apiv1.Node
		pcs      []*schedulingv1.PriorityClass
		pgs      []*schedulingv1beta1.PodGroup
		expected map[string]string
	}{
		{
			name:  "pod-deallocate",
			pods:  []*apiv1.Pod{w1, w2, w3},
			nodes: []*apiv1.Node{n1, n2},
			pcs:   []*schedulingv1.PriorityClass{p1, p2},
			pgs:   []*schedulingv1beta1.PodGroup{pg1, pg2},
			expected: map[string]string{ // podKey -> node
				"ns1/worker-3": "node1",
			},
		},
	}

	for _, test := range tests {
		// initialize schedulerCache
		binder := &util.FakeBinder{
			Binds:   map[string]string{},
			Channel: make(chan string, 10),
		}
		recorder := record.NewFakeRecorder(100)
		go func() {
			for {
				event := <-recorder.Events
				t.Logf("%s: [Event] %s", test.name, event)
			}
		}()
		for _, node := range test.nodes {
			schedulerCache.AddOrUpdateNode(node)
		}
		for _, pod := range test.pods {
			schedulerCache.AddPod(pod)
		}
		for _, pc := range test.pcs {
			schedulerCache.PriorityClasses[pc.Name] = pc
		}
		for _, pg := range test.pgs {
			pg.Status = schedulingv1beta1.PodGroupStatus{
				Phase: schedulingv1beta1.PodGroupInqueue,
			}
			schedulerCache.AddPodGroupV1beta1(pg)
		}
		schedulerCache.AddQueueV1beta1(queue1)
		// session
		trueValue := true
		ssn := framework.OpenSession(schedulerCache, []conf.Tier{
			{
				Plugins: []conf.PluginOption{
					{
						Name:             PluginName,
						EnabledPredicate: &trueValue,
					},
					{
						Name:                gang.PluginName,
						EnabledJobReady:     &trueValue,
						EnabledJobPipelined: &trueValue,
					},
					{
						Name:            priority.PluginName,
						EnabledJobOrder: &trueValue,
					},
				},
			},
		}, nil)
		// allocate
		allocator := allocate.New()
		allocator.Execute(ssn)
		framework.CloseSession(ssn)

		t.Logf("expected: %#v, got: %#v", test.expected, binder.Binds)
		if !reflect.DeepEqual(test.expected, binder.Binds) {
			t.Errorf("expected: %v, got %v ", test.expected, binder.Binds)
		}
	}
}
