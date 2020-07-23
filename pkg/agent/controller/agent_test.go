package controller_test

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/submariner-io/admiral/pkg/fake"
	"github.com/submariner-io/admiral/pkg/syncer/broker"
	"github.com/submariner-io/admiral/pkg/syncer/test"
	"github.com/submariner-io/lighthouse/pkg/agent/controller"
	lighthousev2a1 "github.com/submariner-io/lighthouse/pkg/apis/lighthouse.submariner.io/v2alpha1"
	lighthouseClientset "github.com/submariner-io/lighthouse/pkg/client/clientset/versioned"
	fakeLighthouseClientset "github.com/submariner-io/lighthouse/pkg/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	fakeKubeCLient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

const clusterID = "east"

var _ = Describe("ServiceImport syncing", func() {
	t := newTestDiver()

	When("a ServiceExport is created", func() {
		When("the Service already exists", func() {
			It("should correctly sync a ServiceImport and update the ServiceExport status", func() {
				t.createService()
				t.createServiceExport()
				t.awaitServiceExported(t.service.Spec.ClusterIP)
			})
		})

		When("the Service doesn't initially exist", func() {
			It("should initially update the ServiceExport status to Initialized and eventually sync a ServiceImport", func() {
				t.createServiceExport()

				t.awaitServiceExportStatus(&lighthousev2a1.ServiceExportCondition{
					Type:   lighthousev2a1.ServiceExportInitialized,
					Status: corev1.ConditionFalse,
				})

				t.createService()
				t.awaitServiceExported(t.service.Spec.ClusterIP)
			})
		})
	})

	When("a ServiceExport is deleted after a ServiceImport is synced", func() {
		It("should delete the ServiceImport", func() {
			t.createService()
			t.createServiceExport()
			t.awaitServiceExported(t.service.Spec.ClusterIP)

			t.deleteServiceExport()
			t.awaitNoServiceImport(t.brokerServiceImportClient)
			t.awaitNoServiceImport(t.localServiceImportClient)
		})
	})

	When("an exported Service is deleted while the ServiceExport still exists", func() {
		It("should delete the ServiceImport", func() {
			t.createService()
			t.createServiceExport()
			t.awaitServiceExported(t.service.Spec.ClusterIP)

			t.deleteService()
			t.awaitNoServiceImport(t.brokerServiceImportClient)
			t.awaitNoServiceImport(t.localServiceImportClient)
			t.awaitServiceExportStatus(&lighthousev2a1.ServiceExportCondition{
				Type:   lighthousev2a1.ServiceExportInitialized,
				Status: corev1.ConditionFalse,
			})
		})
	})
})

var _ = Describe("Globalnet enabled", func() {
	t := newTestDiver()

	globalIP := "192.168.10.34"
	t.agentSpec.GlobalnetEnabled = true

	JustBeforeEach(func() {
		t.createService()
		t.createServiceExport()
	})

	When("a local ServiceExport is created and the Service has a global IP", func() {
		BeforeEach(func() {
			t.service.SetAnnotations(map[string]string{"submariner.io/globalIp": globalIP})
		})

		It("should sync a ServiceImport with the global IP of the Service", func() {
			t.awaitServiceExported(globalIP)
		})
	})

	When("a local ServiceExport is created and the Service does not initially have a global IP", func() {
		It("should eventually sync a ServiceImport with the global IP of the Service", func() {
			t.awaitServiceExportStatus(&lighthousev2a1.ServiceExportCondition{
				Type:   lighthousev2a1.ServiceExportInitialized,
				Status: corev1.ConditionFalse,
			})

			t.service.SetAnnotations(map[string]string{"submariner.io/globalIp": globalIP})
			_, err := t.localServiceClient.CoreV1().Services(t.service.Namespace).Update(t.service)
			Expect(err).To(Succeed())

			t.awaitServiceExported(globalIP)
		})
	})
})

type testDriver struct {
	agentController           *controller.Controller
	agentSpec                 *controller.AgentSpecification
	localDynClient            dynamic.Interface
	localServiceExportClient  dynamic.ResourceInterface
	localServiceImportClient  dynamic.ResourceInterface
	brokerServiceImportClient dynamic.ResourceInterface
	localServiceClient        kubernetes.Interface
	lighthouseClient          lighthouseClientset.Interface
	initialResources          []runtime.Object
	service                   *corev1.Service
	serviceExport             *lighthousev2a1.ServiceExport
	stopCh                    chan struct{}
}

func newTestDiver() *testDriver {
	t := &testDriver{agentSpec: &controller.AgentSpecification{
		ClusterID:        clusterID,
		Namespace:        test.LocalNamespace,
		GlobalnetEnabled: false,
	}}

	BeforeEach(func() {
		t.initialResources = nil
		t.stopCh = make(chan struct{})

		t.service = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: test.LocalNamespace,
			},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.253.9.1",
			},
		}

		t.serviceExport = &lighthousev2a1.ServiceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      t.service.Name,
				Namespace: t.service.Namespace,
			},
		}
	})

	JustBeforeEach(func() {
		restMapper := test.GetRESTMapperFor(&lighthousev2a1.ServiceExport{}, &lighthousev2a1.ServiceImport{}, &corev1.Service{})

		t.localDynClient = fake.NewDynamicClient(test.PrepInitialClientObjs("", "", t.initialResources...)...)
		brokerDynClient := fake.NewDynamicClient()

		t.localServiceExportClient = t.localDynClient.Resource(*test.GetGroupVersionResourceFor(restMapper,
			&lighthousev2a1.ServiceExport{})).Namespace(test.LocalNamespace)

		t.localServiceImportClient = t.localDynClient.Resource(*test.GetGroupVersionResourceFor(restMapper,
			&lighthousev2a1.ServiceImport{})).Namespace(test.LocalNamespace)

		t.brokerServiceImportClient = brokerDynClient.Resource(*test.GetGroupVersionResourceFor(restMapper,
			&lighthousev2a1.ServiceImport{})).Namespace(test.RemoteNamespace)

		t.localServiceClient = fakeKubeCLient.NewSimpleClientset()

		t.lighthouseClient = fakeLighthouseClientset.NewSimpleClientset(t.serviceExport)

		syncerConfig := &broker.SyncerConfig{
			BrokerNamespace: test.RemoteNamespace,
		}

		syncerScheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(syncerScheme)).To(Succeed())
		Expect(lighthousev2a1.AddToScheme(syncerScheme)).To(Succeed())

		var err error
		t.agentController, err = controller.NewWithDetail(t.agentSpec, syncerConfig, restMapper, t.localDynClient,
			t.localServiceClient, t.lighthouseClient, syncerScheme, func(config *broker.SyncerConfig) (*broker.Syncer, error) {
				return broker.NewSyncerWithDetail(config, t.localDynClient, brokerDynClient, restMapper)
			})

		Expect(err).To(Succeed())

		Expect(t.agentController.Start(t.stopCh)).To(Succeed())
	})

	AfterEach(func() {
		close(t.stopCh)
	})

	return t
}

func (t *testDriver) createService() {
	_, err := t.localServiceClient.CoreV1().Services(t.service.Namespace).Create(t.service)
	Expect(err).To(Succeed())

	rawService := &unstructured.Unstructured{}
	Expect(scheme.Scheme.Convert(t.service, rawService, nil)).To(Succeed())

	_, err = t.dynamicServiceClient().Create(rawService, metav1.CreateOptions{})
	Expect(err).To(Succeed())
}

func (t *testDriver) createServiceExport() {
	test.CreateResource(t.localServiceExportClient, t.serviceExport)
}

func (t *testDriver) deleteServiceExport() {
	Expect(t.localServiceExportClient.Delete(t.service.GetName(), nil)).To(Succeed())
}

func (t *testDriver) deleteService() {
	Expect(t.dynamicServiceClient().Delete(t.service.Name, nil)).To(Succeed())

	Expect(t.localServiceClient.CoreV1().Services(t.service.Namespace).Delete(t.service.Name, nil)).To(Succeed())
}

func (t *testDriver) dynamicServiceClient() dynamic.ResourceInterface {
	return t.localDynClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "services"}).Namespace(t.service.Namespace)
}

func (t *testDriver) awaitServiceImport(client dynamic.ResourceInterface, serviceIP string) {
	obj := test.WaitForResource(client, t.service.Name+"-"+t.service.Namespace+"-"+clusterID)

	serviceImport := &lighthousev2a1.ServiceImport{}
	Expect(scheme.Scheme.Convert(obj, serviceImport, nil)).To(Succeed())

	Expect(serviceImport.GetAnnotations()["origin-name"]).To(Equal(t.service.Name))
	Expect(serviceImport.GetAnnotations()["origin-namespace"]).To(Equal(t.service.Namespace))
	Expect(serviceImport.Spec.Type).To(Equal(lighthousev2a1.SuperclusterIP))

	Expect(serviceImport.Status.Clusters).To(HaveLen(1))
	Expect(serviceImport.Status.Clusters[0].Cluster).To(Equal(clusterID))
	Expect(serviceImport.Status.Clusters[0].IPs).To(HaveLen(1))
	Expect(serviceImport.Status.Clusters[0].IPs[0]).To(Equal(serviceIP))
}

func (t *testDriver) awaitNoServiceImport(client dynamic.ResourceInterface) {
	test.WaitForNoResource(client, t.service.Name+"-"+t.service.Namespace+"-"+clusterID)
}

func (t *testDriver) awaitServiceExportStatus(expCond *lighthousev2a1.ServiceExportCondition) {
	var found *lighthousev2a1.ServiceExport

	err := wait.PollImmediate(50*time.Millisecond, 5*time.Second, func() (bool, error) {
		se, err := t.lighthouseClient.LighthouseV2alpha1().ServiceExports(t.service.Namespace).Get(t.service.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}

			return false, err
		}

		found = se

		return len(se.Status.Conditions) > 0 && se.Status.Conditions[0].Type == expCond.Type &&
			se.Status.Conditions[0].Status == expCond.Status, nil
	})

	if err == wait.ErrWaitTimeout {
		if found == nil {
			Fail("ServiceExport not found")
		}
	} else {
		Expect(err).To(Succeed())
	}

	Expect(found.Status.Conditions).To(HaveLen(1))
	Expect(found.Status.Conditions[0].Type).To(Equal(expCond.Type))
	Expect(found.Status.Conditions[0].Status).To(Equal(expCond.Status))
	Expect(found.Status.Conditions[0].Message).To(Not(BeNil()))
}

func (t *testDriver) awaitServiceExported(serviceIP string) {
	t.awaitServiceImport(t.brokerServiceImportClient, serviceIP)
	t.awaitServiceImport(t.localServiceImportClient, serviceIP)

	t.awaitServiceExportStatus(&lighthousev2a1.ServiceExportCondition{
		Type:   lighthousev2a1.ServiceExportExported,
		Status: corev1.ConditionTrue,
	})
}