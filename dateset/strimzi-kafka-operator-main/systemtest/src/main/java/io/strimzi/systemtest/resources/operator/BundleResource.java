/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.systemtest.resources.operator;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.fabric8.kubernetes.api.model.EnvVar;
import io.fabric8.kubernetes.api.model.LocalObjectReference;
import io.fabric8.kubernetes.api.model.Quantity;
import io.fabric8.kubernetes.api.model.ResourceRequirements;
import io.fabric8.kubernetes.api.model.ResourceRequirementsBuilder;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.api.model.apps.DeploymentBuilder;
import io.strimzi.systemtest.Environment;
import io.strimzi.systemtest.TestConstants;
import io.strimzi.systemtest.enums.DeploymentTypes;
import io.strimzi.systemtest.resources.ResourceManager;
import io.strimzi.systemtest.resources.ResourceType;
import io.strimzi.systemtest.resources.kubernetes.DeploymentResource;
import io.strimzi.systemtest.utils.StUtils;
import io.strimzi.systemtest.utils.kubeUtils.controllers.DeploymentUtils;
import io.strimzi.test.TestUtils;
import io.strimzi.test.k8s.KubeClusterResource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class BundleResource implements ResourceType<Deployment> {
    public static final String PATH_TO_CO_CONFIG = TestUtils.USER_PATH + "/../packaging/install/cluster-operator/060-Deployment-strimzi-cluster-operator.yaml";

    private String name;
    private String namespaceInstallTo;
    private String namespaceToWatch;
    private long operationTimeout;
    private long reconciliationInterval;
    private List<EnvVar> extraEnvVars;
    private Map<String, String> extraLabels;
    private int replicas = 1;

    @Override
    public String getKind() {
        return TestConstants.DEPLOYMENT;
    }
    @Override
    public Deployment get(String namespace, String name) {
        String deploymentName = ResourceManager.kubeClient().namespace(namespace).getDeploymentNameByPrefix(name);
        return deploymentName != null ? ResourceManager.kubeClient().getDeployment(namespace, deploymentName) : null;
    }
    @Override
    public void create(Deployment resource) {
        ResourceManager.kubeClient().createDeployment(resource);
    }
    @Override
    public void delete(Deployment resource) {
        ResourceManager.kubeClient().deleteDeployment(resource.getMetadata().getNamespace(), resource.getMetadata().getName());
    }

    @Override
    public void update(Deployment resource) {
        ResourceManager.kubeClient().updateDeployment(resource);
    }

    @Override
    @SuppressFBWarnings(value = "RCN_REDUNDANT_NULLCHECK_WOULD_HAVE_BEEN_A_NPE")
    public boolean waitForReadiness(Deployment resource) {
        return resource != null
            && resource.getMetadata() != null
            && resource.getMetadata().getName() != null
            && resource.getStatus() != null
            && DeploymentUtils.waitForDeploymentAndPodsReady(resource.getMetadata().getNamespace(), resource.getMetadata().getName(), resource.getSpec().getReplicas());
    }

    // this is for resourceTypes inside ResourceManager
    public BundleResource() {}

    private BundleResource(BundleResourceBuilder builder) {
        this.name = builder.name;
        this.namespaceInstallTo = builder.namespaceInstallTo;
        this.namespaceToWatch = builder.namespaceToWatch;
        this.operationTimeout = builder.operationTimeout;
        this.reconciliationInterval = builder.reconciliationInterval;
        this.extraEnvVars = builder.extraEnvVars;
        this.extraLabels = builder.extraLabels;
        this.replicas = builder.replicas;

        // assign defaults is something is not specified
        if (this.name == null || this.name.isEmpty()) this.name = TestConstants.STRIMZI_DEPLOYMENT_NAME;
        if (this.namespaceToWatch == null) this.namespaceToWatch = this.namespaceInstallTo;
        if (this.operationTimeout == 0) this.operationTimeout = TestConstants.CO_OPERATION_TIMEOUT_DEFAULT;
        if (this.reconciliationInterval == 0) this.reconciliationInterval = TestConstants.RECONCILIATION_INTERVAL;
        if (this.extraEnvVars == null) this.extraEnvVars = new ArrayList<>();
        if (this.extraLabels == null) this.extraLabels = new HashMap<>();
    }

    public static class BundleResourceBuilder {

        private String name;
        private String namespaceInstallTo;
        private String namespaceToWatch;
        private long operationTimeout;
        private long reconciliationInterval;
        private List<EnvVar> extraEnvVars;
        private Map<String, String> extraLabels;
        private int replicas;

        public BundleResourceBuilder withName(String name) {
            this.name = name;
            return self();
        }

        public BundleResourceBuilder withNamespace(String namespaceInstallTo) {
            this.namespaceInstallTo = namespaceInstallTo;
            return self();
        }
        public BundleResourceBuilder withWatchingNamespaces(String namespaceToWatch) {
            this.namespaceToWatch = namespaceToWatch;
            return self();
        }
        public BundleResourceBuilder withOperationTimeout(long operationTimeout) {
            this.operationTimeout = operationTimeout;
            return self();
        }
        public BundleResourceBuilder withReconciliationInterval(long reconciliationInterval) {
            this.reconciliationInterval = reconciliationInterval;
            return self();
        }

        public BundleResourceBuilder withExtraEnvVars(List<EnvVar> extraEnvVars) {
            this.extraEnvVars = extraEnvVars;
            return self();
        }

        public BundleResourceBuilder withExtraLabels(Map<String, String> extraLabels) {
            this.extraLabels = extraLabels;
            return self();
        }

        public BundleResourceBuilder withReplicas(int replicas) {
            this.replicas = replicas;
            return self();
        }

        protected BundleResourceBuilder self() {
            return this;
        }

        public BundleResourceBuilder defaultConfigurationWithNamespace(String namespaceName) {
            this.name = TestConstants.STRIMZI_DEPLOYMENT_NAME;
            this.namespaceInstallTo = namespaceName;
            this.namespaceToWatch = this.namespaceInstallTo;
            this.operationTimeout = TestConstants.CO_OPERATION_TIMEOUT_DEFAULT;
            this.reconciliationInterval = TestConstants.RECONCILIATION_INTERVAL;
            return self();
        }

        public BundleResource buildBundleInstance() {
            return new BundleResource(this);
        }
    }

    protected BundleResourceBuilder newBuilder() {
        return new BundleResourceBuilder();
    };

    protected BundleResourceBuilder toBuilder() {
        return newBuilder()
            .withName(name)
            .withNamespace(namespaceInstallTo)
            .withWatchingNamespaces(namespaceToWatch)
            .withOperationTimeout(operationTimeout)
            .withReconciliationInterval(reconciliationInterval)
            .withExtraEnvVars(extraEnvVars)
            .withReplicas(replicas);
    }

    public DeploymentBuilder buildBundleDeployment() {
        Deployment clusterOperator = DeploymentResource.getDeploymentFromYaml(PATH_TO_CO_CONFIG);

        // Get env from config file
        List<EnvVar> envVars = clusterOperator.getSpec().getTemplate().getSpec().getContainers().get(0).getEnv();
        // Get default CO image
        String coImage = clusterOperator.getSpec().getTemplate().getSpec().getContainers().get(0).getImage();

        // Update images
        for (EnvVar envVar : envVars) {
            switch (envVar.getName()) {
                case "STRIMZI_NAMESPACE":
                    envVar.setValue(namespaceToWatch);
                    envVar.setValueFrom(null);
                    break;
                case "STRIMZI_FULL_RECONCILIATION_INTERVAL_MS":
                    envVar.setValue(Long.toString(reconciliationInterval));
                    break;
                case "STRIMZI_OPERATION_TIMEOUT_MS":
                    envVar.setValue(Long.toString(operationTimeout));
                    break;
                case "STRIMZI_FEATURE_GATES":
                    if (!envVar.getValue().equals(Environment.STRIMZI_FEATURE_GATES)) {
                        envVar.setValue(Environment.STRIMZI_FEATURE_GATES);
                    }
                    break;
                default:
                    if (envVar.getName().contains("KAFKA_BRIDGE_IMAGE")) {
                        envVar.setValue(Environment.useLatestReleasedBridge() ? envVar.getValue() : Environment.BRIDGE_IMAGE);
                    } else if (envVar.getName().contains("STRIMZI_DEFAULT")) {
                        envVar.setValue(StUtils.changeOrgAndTag(envVar.getValue()));
                    } else if (envVar.getName().contains("IMAGES")) {
                        envVar.setValue(StUtils.changeOrgAndTagInImageMap(envVar.getValue()));
                    }
            }
        }

        envVars.add(new EnvVar("STRIMZI_IMAGE_PULL_POLICY", Environment.COMPONENTS_IMAGE_PULL_POLICY, null));
        envVars.add(new EnvVar("STRIMZI_LOG_LEVEL", Environment.STRIMZI_LOG_LEVEL, null));

        if (extraEnvVars != null) {

            envVars.forEach(envVar -> extraEnvVars.stream()
                .filter(extraVar -> envVar.getName().equals(extraVar.getName()))
                .findFirst()
                .ifPresent(xVar -> envVar.setValue(xVar.getValue()))
            );
        }

        if (Environment.SYSTEM_TEST_STRIMZI_IMAGE_PULL_SECRET != null && !Environment.SYSTEM_TEST_STRIMZI_IMAGE_PULL_SECRET.isEmpty()) {
            // for strimzi-operator
            List<LocalObjectReference> imagePullSecrets = Collections.singletonList(new LocalObjectReference(Environment.SYSTEM_TEST_STRIMZI_IMAGE_PULL_SECRET));
            clusterOperator.getSpec().getTemplate().getSpec().setImagePullSecrets(imagePullSecrets);
            // for kafka
            envVars.add(new EnvVar("STRIMZI_IMAGE_PULL_SECRETS", Environment.SYSTEM_TEST_STRIMZI_IMAGE_PULL_SECRET, null));
        }
        // adding custom evn vars specified by user in installation
        if (extraEnvVars != null) {
            envVars.addAll(extraEnvVars);
        }
        // Remove duplicates from envVars
        List<EnvVar> envVarsWithoutDuplicates = envVars.stream()
            .distinct()
            .collect(Collectors.toList());

        // Apply updated env variables
        clusterOperator.getSpec().getTemplate().getSpec().getContainers().get(0).setEnv(envVarsWithoutDuplicates);

        // Change default values for Cluster Operator memory when RESOURCE_ALLOCATION_STRATEGY is not set to NOT_SHARED
        if (KubeClusterResource.getInstance().fipsEnabled()) {
            ResourceRequirements resourceRequirements = new ResourceRequirementsBuilder()
                .withRequests(Map.of("memory", new Quantity(TestConstants.CO_REQUESTS_MEMORY), "cpu", new Quantity(
                    TestConstants.CO_REQUESTS_CPU)))
                .withLimits(Map.of("memory", new Quantity(TestConstants.CO_LIMITS_MEMORY), "cpu", new Quantity(
                    TestConstants.CO_LIMITS_CPU)))
                .build();

            clusterOperator.getSpec().getTemplate().getSpec().getContainers().get(0).setResources(resourceRequirements);
        }

        return new DeploymentBuilder(clusterOperator)
            .editMetadata()
                .withName(name)
                .withNamespace(namespaceInstallTo)
                .addToLabels(TestConstants.DEPLOYMENT_TYPE, DeploymentTypes.BundleClusterOperator.name())
            .endMetadata()
            .editSpec()
                .withReplicas(this.replicas)
                .withNewSelector()
                    .addToMatchLabels("name", TestConstants.STRIMZI_DEPLOYMENT_NAME)
                    .addToMatchLabels(this.extraLabels)
                .endSelector()
                .editTemplate()
                    .editMetadata()
                        .addToLabels(this.extraLabels)
                    .endMetadata()
                    .editSpec()
                        .editFirstContainer()
                            .withImage(StUtils.changeOrgAndTag(coImage))
                            .withImagePullPolicy(Environment.OPERATOR_IMAGE_PULL_POLICY)
                        .endContainer()
                        .editFirstVolume()
                            .editEmptyDir()
                                // in case we execute more than 10 test cases in parallel we at least 2Mi storage
                                .withNewSizeLimit("2Mi")
                            .endEmptyDir()
                        .endVolume()
                        .editLastVolume()
                            .editConfigMap()
                                .withName(name)
                            .endConfigMap()
                        .endVolume()
                    .endSpec()
                .endTemplate()
            .endSpec();
    }
}
