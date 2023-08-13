package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	kubeconfig := flag.String("kubeconfig", "KUBECONFIG", "location of kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err)
	}

	// Create the dynamic client
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating dynamic client: %v\n", err)
		os.Exit(1)
	}

	// Define the CRD schema with the correct API Group and Version
	crdSchema := schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1beta1",
		Resource: "vulnerabilitymanifestsummaries",
	}

	// Get the CRD object from the Kubernetes API server
	crdObj, err := dynamicClient.Resource(crdSchema).Namespace("kubescape").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting CRD object: %v\n", err)
		os.Exit(1)
	}

	// Display the CRD objects
	for _, obj := range crdObj.Items {
		fmt.Println("CRD Object:")
		fmt.Printf("%s\n", obj)
	}

}
