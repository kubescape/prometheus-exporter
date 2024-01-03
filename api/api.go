package api

import (
	"context"
	"errors"
	"flag"
	"path/filepath"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
)

type StorageClientImpl struct {
	clientset *spdxclient.Clientset
}

var _ StorageClient = &StorageClientImpl{}

func NewStorageClient() *StorageClientImpl {
	clusterConfig, err := getConfig()
	if err != nil {
		logger.L().Fatal("error getting cluster config", helpers.Error(err))
	}
	// Create the dynamic client
	clientset, err := spdxclient.NewForConfig(clusterConfig)
	if err != nil {
		logger.L().Fatal("error creating dynamic client", helpers.Error(err))
	}
	return &StorageClientImpl{
		clientset: clientset,
	}
}

func getConfig() (*rest.Config, error) {
	// try in-cluster config first
	clusterConfig, err := rest.InClusterConfig()
	if err == nil {
		return clusterConfig, nil
	}
	// fallback to kubeconfig
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()
	clusterConfig, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err == nil {
		return clusterConfig, nil
	}
	// nothing works
	return nil, errors.New("unable to find config")
}

func (sc *StorageClientImpl) GetVulnerabilitySummaries() (*v1beta1.VulnerabilitySummaryList, error) {
	vulnsummary, err := sc.clientset.SpdxV1beta1().VulnerabilitySummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return vulnsummary, nil

}

func (sc *StorageClientImpl) GetConfigScanSummaries() (*v1beta1.ConfigurationScanSummaryList, error) {
	configscan, err := sc.clientset.SpdxV1beta1().ConfigurationScanSummaries("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return configscan, nil

}
