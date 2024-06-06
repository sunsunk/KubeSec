package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Subject struct {
	Kind  string   `json:"kind"`
	Names []string `json:"name"`
}
type ClusterRoleBinding struct {
	Namespace   string      `json:"rb_namespace"`
	Name        string      `json:"rb_names"`
	Subject     Subject     `json:"subject"`
	ClusterRole ClusterRole `json:"cluster_cole"`
}
type ClusterRole struct {
	Namespace string   `json:"cluster_role.namespace"`
	Name      string   `json:"cluster_role.name"`
	Resources []string `json:"cluster_role.resources"`
	Verbs     []string `json:"cluster_role.verbs"`
}

func main() {

	kubeconfig := flag.String("kubeconfig", filepath.Join(
		homeDir(), ".kube", "config"), "absolute path to the kubeconfig file")

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	for _, clusterRoleBinding := range clusterRoleBindings.Items {
		fmt.Println("ClusterRoleBinding:", clusterRoleBinding.Name)
		fmt.Println("Subjects:")
		subject_ := Subject{}

		for _, subject := range clusterRoleBinding.Subjects {

			subject_.Names = append(subject_.Names, subject.Name)
		}

		subjects := clusterRoleBinding.Subjects
		for _, subject := range subjects {

			fmt.Println(subject)
		}
		fmt.Println("============================")

		for _, role := range clusterRoles.Items {
			if clusterRoleBinding.RoleRef.Name == role.Name {

				clstRole_ := ClusterRole{
					Namespace: role.Namespace,
					Name:      role.Name,
				}
				clstroleBinding := ClusterRoleBinding{
					Namespace: clusterRoleBinding.Namespace,
					Name:      clusterRoleBinding.Name,
				}
				for _, rule := range role.Rules {

					clstRole_.Resources = append(clstRole_.Resources, "###")
					for _, resource := range rule.Resources {
						clstRole_.Resources = append(clstRole_.Resources, resource)

					}

					clstRole_.Resources = append(clstRole_.Resources, "###")

					clstRole_.Verbs = append(clstRole_.Verbs, "###")
					for _, verb := range rule.Verbs {

						clstRole_.Verbs = append(clstRole_.Verbs, verb)

					}
					clstRole_.Verbs = append(clstRole_.Verbs, "###")
				}
				clstroleBinding.ClusterRole = clstRole_
				clstroleBinding.Subject = subject_
				jsonData, err := json.Marshal(clstroleBinding)
				if err != nil {
					fmt.Println("JSON encoding error:", err)
					return
				}
				fmt.Println(string(jsonData))
				file, err := os.OpenFile("clusterRoleBindingInfo.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					fmt.Println("Error opening file:", err)
					return
				}
				defer file.Close()
				_, err = file.Write(jsonData)
				file.WriteString("\n")

				if err != nil {
					fmt.Println("Error writing to file:", err)
					return
				}

				fmt.Println("JSON data appended to file.")
			}
		}
	}
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE")
}
