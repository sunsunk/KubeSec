package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Subject struct {
	Kind  string   `json:"kind"`
	Names []string `json:"name"`
}
type RoleBinding struct {
	Namespace string  `json:"rb_namespace"`
	Name      string  `json:"rb_names"`
	Subject   Subject `json:"subject"`
	Role      Role    `json:"role"`
}
type Role struct {
	Namespace string   `json:"role.namespace"`
	Name      string   `json:"role.name"`
	Resources []string `json:"role.resources"`
	Verbs     []string `json:"role.verbs"`
}

func getRolesBindings() {

	kubeconfig := flag.String("kubeconfig", filepath.Join(os.Getenv("HOME"), ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	rolebindings, err := clientset.RbacV1().RoleBindings("").List(context.TODO(), v1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	roles, err := clientset.RbacV1().Roles("").List(context.TODO(), v1.ListOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("rb.Namespace\trb.Name\trb.RoleRef.Name\trb.Subjects.Name\n")
	fmt.Printf("===========================================\n")

	for _, rb := range rolebindings.Items {

		subject_ := Subject{}
		for _, subject := range rb.Subjects {

			subject_.Names = append(subject_.Names, subject.Name)
		}
		fmt.Println()
		for _, role := range roles.Items {

			if rb.RoleRef.Name == role.Name {

				role_ := Role{
					Namespace: role.Namespace,
					Name:      role.Name,
				}
				roleBinding := RoleBinding{
					Namespace: rb.Namespace,
					Name:      rb.Name,
				}

				for _, rule := range role.Rules {
					role_.Resources = append(role_.Resources, "###")
					for _, resource := range rule.Resources {
						role_.Resources = append(role_.Resources, resource)
					}

					role_.Resources = append(role_.Resources, "###")

					role_.Verbs = append(role_.Verbs, "###")
					for _, verb := range rule.Verbs {

						role_.Verbs = append(role_.Verbs, verb)

					}
					role_.Verbs = append(role_.Verbs, "###")
				}
				roleBinding.Role = role_
				roleBinding.Subject = subject_
				jsonData, err := json.Marshal(roleBinding)
				if err != nil {
					fmt.Println("JSON encoding error:", err)
					return
				}
				fmt.Println(string(jsonData))

				file, err := os.OpenFile("jsonData.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	if h := homeDirFromEnv(); h != "" {
		return h
	}
	return homeDirFromUser()
}

func homeDirFromEnv() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if h := os.Getenv("USERPROFILE"); h != "" {
		return h
	}
	return ""
}

func homeDirFromUser() string {
	u, err := user.Current()
	if err == nil {
		return u.HomeDir
	}
	return ""
}
func main() {
	getRolesBindings()
}
