package clusterd

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Context struct {
	// The kubernetes config used for this context
	KubeConfig *rest.Config

	// Clientset is a connection to the core kubernetes API
	Clientset kubernetes.Interface

	// Represents the Client provided by the controller-runtime package to interact with Kubernetes objects
	Client client.Client
}
