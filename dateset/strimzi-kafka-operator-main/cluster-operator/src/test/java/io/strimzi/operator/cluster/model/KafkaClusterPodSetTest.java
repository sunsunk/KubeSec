/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.model;

import io.fabric8.kubernetes.api.model.Affinity;
import io.fabric8.kubernetes.api.model.AffinityBuilder;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.EnvVar;
import io.fabric8.kubernetes.api.model.HostAlias;
import io.fabric8.kubernetes.api.model.HostAliasBuilder;
import io.fabric8.kubernetes.api.model.LabelSelectorBuilder;
import io.fabric8.kubernetes.api.model.LocalObjectReference;
import io.fabric8.kubernetes.api.model.NodeSelectorTermBuilder;
import io.fabric8.kubernetes.api.model.PersistentVolumeClaim;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodSecurityContextBuilder;
import io.fabric8.kubernetes.api.model.Quantity;
import io.fabric8.kubernetes.api.model.SecurityContext;
import io.fabric8.kubernetes.api.model.SecurityContextBuilder;
import io.fabric8.kubernetes.api.model.Toleration;
import io.fabric8.kubernetes.api.model.TolerationBuilder;
import io.fabric8.kubernetes.api.model.TopologySpreadConstraint;
import io.fabric8.kubernetes.api.model.TopologySpreadConstraintBuilder;
import io.strimzi.api.kafka.model.common.ContainerEnvVar;
import io.strimzi.api.kafka.model.common.JvmOptions;
import io.strimzi.api.kafka.model.common.Probe;
import io.strimzi.api.kafka.model.kafka.JbodStorageBuilder;
import io.strimzi.api.kafka.model.kafka.Kafka;
import io.strimzi.api.kafka.model.kafka.KafkaBuilder;
import io.strimzi.api.kafka.model.kafka.KafkaResources;
import io.strimzi.api.kafka.model.kafka.PersistentClaimStorageBuilder;
import io.strimzi.api.kafka.model.kafka.listener.GenericKafkaListenerBuilder;
import io.strimzi.api.kafka.model.kafka.listener.KafkaListenerType;
import io.strimzi.api.kafka.model.podset.StrimziPodSet;
import io.strimzi.operator.cluster.KafkaVersionTestUtils;
import io.strimzi.operator.cluster.PlatformFeaturesAvailability;
import io.strimzi.operator.cluster.model.nodepools.NodePoolUtils;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.platform.KubernetesVersion;
import io.strimzi.plugin.security.profiles.impl.RestrictedPodSecurityProvider;
import io.strimzi.test.TestUtils;
import io.strimzi.test.annotations.ParallelSuite;
import io.strimzi.test.annotations.ParallelTest;
import org.hamcrest.Matchers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasProperty;

@SuppressWarnings({"checkstyle:ClassDataAbstractionCoupling", "checkstyle:ClassFanOutComplexity"})
@ParallelSuite
public class KafkaClusterPodSetTest {
    private static final KafkaVersion.Lookup VERSIONS = KafkaVersionTestUtils.getKafkaVersionLookup();
    private static final SharedEnvironmentProvider SHARED_ENV_PROVIDER = new MockSharedEnvironmentProvider();
    private static final String NAMESPACE = "my-namespace";
    private static final String CLUSTER = "my-cluster";

    private static final Kafka KAFKA = new KafkaBuilder()
            .withNewMetadata()
                .withName(CLUSTER)
                .withNamespace(NAMESPACE)
            .endMetadata()
            .withNewSpec()
                .withNewZookeeper()
                    .withReplicas(3)
                    .withNewPersistentClaimStorage()
                        .withSize("100Gi")
                    .endPersistentClaimStorage()
                .endZookeeper()
                .withNewKafka()
                    .withReplicas(3)
                    .withListeners(new GenericKafkaListenerBuilder()
                            .withName("plain")
                            .withPort(9092)
                            .withType(KafkaListenerType.INTERNAL)
                            .withTls(false)
                            .build())
                    .withNewJbodStorage()
                        .withVolumes(new PersistentClaimStorageBuilder().withId(0).withSize("100Gi").withDeleteClaim(false).build())
                    .endJbodStorage()
                    .withConfig(Map.of("log.message.format.version", "3.0", "inter.broker.protocol.version", "3.0"))
                .endKafka()
            .endSpec()
            .build();

    private final static List<KafkaPool> POOLS = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, KAFKA, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
    private static final KafkaCluster KC = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, KAFKA, POOLS, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);

    @ParallelTest
    public void testPodSet()   {
        StrimziPodSet ps = KC.generatePodSets(true, null, null, brokerId -> Map.of("test-anno", KC.getPodName(brokerId))).get(0);

        assertThat(ps.getMetadata().getName(), is(KafkaResources.kafkaComponentName(CLUSTER)));
        assertThat(ps.getMetadata().getLabels().entrySet().containsAll(KC.labels.withAdditionalLabels(null).toMap().entrySet()), is(true));
        assertThat(ps.getMetadata().getAnnotations().get(Annotations.ANNO_STRIMZI_IO_STORAGE), is(ModelUtils.encodeStorageToJson(new JbodStorageBuilder().withVolumes(new PersistentClaimStorageBuilder().withId(0).withSize("100Gi").withDeleteClaim(false).build()).build())));
        TestUtils.checkOwnerReference(ps, KAFKA);
        assertThat(ps.getSpec().getSelector().getMatchLabels(), is(KafkaClusterPodSetTest.KC.getSelectorLabels().withStrimziPoolName("kafka").toMap()));
        assertThat(ps.getSpec().getPods().size(), is(3));

        // We need to loop through the pods to make sure they have the right values
        List<Pod> pods = PodSetUtils.podSetToPods(ps);
        for (Pod pod : pods)  {
            assertThat(pod.getMetadata().getLabels().entrySet().containsAll(KC.labels.withStrimziPodName(pod.getMetadata().getName()).withStatefulSetPod(pod.getMetadata().getName()).withStrimziPodSetController(KC.getComponentName()).toMap().entrySet()), is(true));
            assertThat(pod.getMetadata().getAnnotations().size(), is(2));
            assertThat(pod.getMetadata().getAnnotations().get(PodRevision.STRIMZI_REVISION_ANNOTATION), is(notNullValue()));
            assertThat(pod.getMetadata().getAnnotations().get("test-anno"), is(pod.getMetadata().getName()));

            assertThat(pod.getSpec().getHostname(), is(pod.getMetadata().getName()));
            assertThat(pod.getSpec().getSubdomain(), is(KafkaResources.brokersServiceName(CLUSTER)));
            assertThat(pod.getSpec().getRestartPolicy(), is("Always"));
            assertThat(pod.getSpec().getTerminationGracePeriodSeconds(), is(30L));
            assertThat(pod.getSpec().getVolumes().stream()
                    .filter(volume -> volume.getName().equalsIgnoreCase("strimzi-tmp"))
                    .findFirst().orElseThrow().getEmptyDir().getSizeLimit(), is(new Quantity(VolumeUtils.STRIMZI_TMP_DIRECTORY_DEFAULT_SIZE)));

            assertThat(pod.getSpec().getContainers().size(), is(1));
            assertThat(pod.getSpec().getContainers().get(0).getLivenessProbe().getTimeoutSeconds(), is(5));
            assertThat(pod.getSpec().getContainers().get(0).getLivenessProbe().getInitialDelaySeconds(), is(15));
            assertThat(pod.getSpec().getContainers().get(0).getReadinessProbe().getTimeoutSeconds(), is(5));
            assertThat(pod.getSpec().getContainers().get(0).getReadinessProbe().getInitialDelaySeconds(), is(15));
            assertThat(io.strimzi.operator.cluster.TestUtils.containerEnvVars(pod.getSpec().getContainers().get(0)).get(AbstractModel.ENV_VAR_STRIMZI_KAFKA_GC_LOG_ENABLED), is(Boolean.toString(JvmOptions.DEFAULT_GC_LOGGING_ENABLED)));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(0).getName(), is("data-0"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(0).getMountPath(), is("/var/lib/kafka/data-0"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(1).getName(), is(VolumeUtils.STRIMZI_TMP_DIRECTORY_DEFAULT_VOLUME_NAME));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(1).getMountPath(), is(VolumeUtils.STRIMZI_TMP_DIRECTORY_DEFAULT_MOUNT_PATH));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(2).getName(), is(KafkaCluster.CLUSTER_CA_CERTS_VOLUME));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(2).getMountPath(), is(KafkaCluster.CLUSTER_CA_CERTS_VOLUME_MOUNT));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(3).getName(), is(KafkaCluster.BROKER_CERTS_VOLUME));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(3).getMountPath(), is(KafkaCluster.BROKER_CERTS_VOLUME_MOUNT));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(4).getName(), is(KafkaCluster.CLIENT_CA_CERTS_VOLUME));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(4).getMountPath(), is(KafkaCluster.CLIENT_CA_CERTS_VOLUME_MOUNT));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(5).getName(), is("kafka-metrics-and-logging"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(5).getMountPath(), is("/opt/kafka/custom-config/"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(6).getName(), is("ready-files"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(6).getMountPath(), is("/var/opt/kafka"));

            assertThat(pod.getSpec().getVolumes().size(), is(7));
            assertThat(pod.getSpec().getVolumes().get(0).getName(), is("data-0"));
            assertThat(pod.getSpec().getVolumes().get(0).getPersistentVolumeClaim(), is(notNullValue()));
            assertThat(pod.getSpec().getVolumes().get(1).getName(), is(VolumeUtils.STRIMZI_TMP_DIRECTORY_DEFAULT_VOLUME_NAME));
            assertThat(pod.getSpec().getVolumes().get(1).getEmptyDir(), is(notNullValue()));
            assertThat(pod.getSpec().getVolumes().get(2).getName(), is(KafkaCluster.CLUSTER_CA_CERTS_VOLUME));
            assertThat(pod.getSpec().getVolumes().get(2).getSecret().getSecretName(), is("my-cluster-cluster-ca-cert"));
            assertThat(pod.getSpec().getVolumes().get(3).getName(), is(KafkaCluster.BROKER_CERTS_VOLUME));
            assertThat(pod.getSpec().getVolumes().get(3).getSecret().getSecretName(), is("my-cluster-kafka-brokers"));
            assertThat(pod.getSpec().getVolumes().get(4).getName(), is(KafkaCluster.CLIENT_CA_CERTS_VOLUME));
            assertThat(pod.getSpec().getVolumes().get(4).getSecret().getSecretName(), is("my-cluster-clients-ca-cert"));
            assertThat(pod.getSpec().getVolumes().get(5).getName(), is("kafka-metrics-and-logging"));
            assertThat(pod.getSpec().getVolumes().get(5).getConfigMap().getName(), is(pod.getMetadata().getName()));
            assertThat(pod.getSpec().getVolumes().get(6).getName(), is("ready-files"));
            assertThat(pod.getSpec().getVolumes().get(6).getEmptyDir(), is(notNullValue()));
        }
    }

    @ParallelTest
    public void testPerBrokerConfiguration() {
        Map<Integer, Map<String, String>> advertisedHostnames = Map.of(
                0, Map.of("PLAIN_9092", "broker-0"),
                1, Map.of("PLAIN_9092", "broker-1"),
                2, Map.of("PLAIN_9092", "broker-2")
        );
        Map<Integer, Map<String, String>> advertisedPorts = Map.of(
                0, Map.of("PLAIN_9092", "10000"),
                1, Map.of("PLAIN_9092", "10001"),
                2, Map.of("PLAIN_9092", "10002")
        );

        String config = KC.generatePerBrokerConfiguration(2, advertisedHostnames, advertisedPorts);

        assertThat(config, containsString("broker.id=2"));
        assertThat(config, containsString("node.id=2"));
        assertThat(config, containsString("log.dirs=/var/lib/kafka/data-0/kafka-log2"));
        assertThat(config, containsString("advertised.listeners=CONTROLPLANE-9090://my-cluster-kafka-2.my-cluster-kafka-brokers.my-namespace.svc:9090,REPLICATION-9091://my-cluster-kafka-2.my-cluster-kafka-brokers.my-namespace.svc:9091,PLAIN-9092://broker-2:10002"));
    }

    @ParallelTest
    public void testPerBrokerConfigMaps() {
        MetricsAndLogging metricsAndLogging = new MetricsAndLogging(null, null);
        Map<Integer, Map<String, String>> advertisedHostnames = Map.of(
                0, Map.of("PLAIN_9092", "broker-0"),
                1, Map.of("PLAIN_9092", "broker-1"),
                2, Map.of("PLAIN_9092", "broker-2")
        );
        Map<Integer, Map<String, String>> advertisedPorts = Map.of(
                0, Map.of("PLAIN_9092", "9092"),
                1, Map.of("PLAIN_9092", "9092"),
                2, Map.of("PLAIN_9092", "9092")
        );

        List<ConfigMap> cms = KC.generatePerBrokerConfigurationConfigMaps(metricsAndLogging, advertisedHostnames, advertisedPorts);

        assertThat(cms.size(), is(3));

        for (ConfigMap cm : cms)    {
            assertThat(cm.getData().size(), is(4));
            assertThat(cm.getMetadata().getName(), startsWith("my-cluster-kafka-"));
            KC.getSelectorLabels().toMap().forEach((key, value) -> assertThat(cm.getMetadata().getLabels(), hasEntry(key, value)));
            assertThat(cm.getData().get("log4j.properties"), is(notNullValue()));
            assertThat(cm.getData().get("server.config"), is(notNullValue()));
            assertThat(cm.getData().get("listeners.config"), is("PLAIN_9092"));
            assertThat(cm.getData().get("metadata.state"), is(notNullValue()));
        }
    }

    @SuppressWarnings({"checkstyle:MethodLength"})
    @ParallelTest
    public void testCustomizedPodSet()   {
        // Prepare various template values
        Map<String, String> spsLabels = TestUtils.map("l1", "v1", "l2", "v2");
        Map<String, String> spsAnnos = TestUtils.map("a1", "v1", "a2", "v2");

        Map<String, String> podLabels = TestUtils.map("l3", "v3", "l4", "v4");
        Map<String, String> podAnnos = TestUtils.map("a3", "v3", "a4", "v4");

        HostAlias hostAlias1 = new HostAliasBuilder()
                .withHostnames("my-host-1", "my-host-2")
                .withIp("192.168.1.86")
                .build();
        HostAlias hostAlias2 = new HostAliasBuilder()
                .withHostnames("my-host-3")
                .withIp("192.168.1.87")
                .build();

        TopologySpreadConstraint tsc1 = new TopologySpreadConstraintBuilder()
                .withTopologyKey("kubernetes.io/zone")
                .withMaxSkew(1)
                .withWhenUnsatisfiable("DoNotSchedule")
                .withLabelSelector(new LabelSelectorBuilder().withMatchLabels(singletonMap("label", "value")).build())
                .build();

        TopologySpreadConstraint tsc2 = new TopologySpreadConstraintBuilder()
                .withTopologyKey("kubernetes.io/hostname")
                .withMaxSkew(2)
                .withWhenUnsatisfiable("ScheduleAnyway")
                .withLabelSelector(new LabelSelectorBuilder().withMatchLabels(singletonMap("label", "value")).build())
                .build();

        LocalObjectReference secret1 = new LocalObjectReference("some-pull-secret");
        LocalObjectReference secret2 = new LocalObjectReference("some-other-pull-secret");

        Affinity affinity = new AffinityBuilder()
                .withNewNodeAffinity()
                .withNewRequiredDuringSchedulingIgnoredDuringExecution()
                .withNodeSelectorTerms(new NodeSelectorTermBuilder()
                        .addNewMatchExpression()
                        .withKey("key1")
                        .withOperator("In")
                        .withValues("value1", "value2")
                        .endMatchExpression()
                        .build())
                .endRequiredDuringSchedulingIgnoredDuringExecution()
                .endNodeAffinity()
                .build();

        List<Toleration> toleration = singletonList(new TolerationBuilder()
                .withEffect("NoExecute")
                .withKey("key1")
                .withOperator("Equal")
                .withValue("value1")
                .build());

        ContainerEnvVar envVar1 = new ContainerEnvVar();
        String testEnvOneKey = "TEST_ENV_1";
        String testEnvOneValue = "test.env.one";
        envVar1.setName(testEnvOneKey);
        envVar1.setValue(testEnvOneValue);

        ContainerEnvVar envVar2 = new ContainerEnvVar();
        String testEnvTwoKey = "TEST_ENV_2";
        String testEnvTwoValue = "test.env.two";
        envVar2.setName(testEnvTwoKey);
        envVar2.setValue(testEnvTwoValue);

        SecurityContext securityContext = new SecurityContextBuilder()
                .withPrivileged(false)
                .withReadOnlyRootFilesystem(false)
                .withAllowPrivilegeEscalation(false)
                .withRunAsNonRoot(true)
                .withNewCapabilities()
                    .addToDrop("ALL")
                .endCapabilities()
                .build();

        String image = "my-custom-image:latest";

        Probe livenessProbe = new Probe();
        livenessProbe.setInitialDelaySeconds(1);
        livenessProbe.setTimeoutSeconds(2);
        livenessProbe.setSuccessThreshold(3);
        livenessProbe.setFailureThreshold(4);
        livenessProbe.setPeriodSeconds(5);

        Probe readinessProbe = new Probe();
        readinessProbe.setInitialDelaySeconds(6);
        readinessProbe.setTimeoutSeconds(7);
        readinessProbe.setSuccessThreshold(8);
        readinessProbe.setFailureThreshold(9);
        readinessProbe.setPeriodSeconds(10);

        // Use the template values in Kafka CR
        Kafka kafka = new KafkaBuilder(KAFKA)
                .editSpec()
                    .editKafka()
                        .withImage(image)
                        .withNewJvmOptions()
                            .withGcLoggingEnabled(true)
                        .endJvmOptions()
                        .withReadinessProbe(readinessProbe)
                        .withLivenessProbe(livenessProbe)
                        .withConfig(Map.of("foo", "bar"))
                        .withNewTemplate()
                            .withNewPodSet()
                                .withNewMetadata()
                                    .withLabels(spsLabels)
                                    .withAnnotations(spsAnnos)
                                .endMetadata()
                            .endPodSet()
                            .withNewPod()
                                .withNewMetadata()
                                    .withLabels(podLabels)
                                    .withAnnotations(podAnnos)
                                .endMetadata()
                                .withPriorityClassName("top-priority")
                                .withSchedulerName("my-scheduler")
                                .withHostAliases(hostAlias1, hostAlias2)
                                .withTopologySpreadConstraints(tsc1, tsc2)
                                .withAffinity(affinity)
                                .withTolerations(toleration)
                                .withEnableServiceLinks(false)
                                .withTmpDirSizeLimit("10Mi")
                                .withTerminationGracePeriodSeconds(123)
                                .withImagePullSecrets(secret1, secret2)
                                .withSecurityContext(new PodSecurityContextBuilder().withFsGroup(123L).withRunAsGroup(456L).withRunAsUser(789L).build())
                            .endPod()
                            .withNewKafkaContainer()
                                .withEnv(envVar1, envVar2)
                                .withSecurityContext(securityContext)
                            .endKafkaContainer()
                        .endTemplate()
                    .endKafka()
                .endSpec()
                .build();

        // Test the resources
        List<KafkaPool> pools = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, kafka, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
        KafkaCluster kc = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kafka, pools, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);
        StrimziPodSet ps = kc.generatePodSets(true, null, null, brokerId -> Map.of("special", "annotation")).get(0);

        assertThat(ps.getMetadata().getName(), is(KafkaResources.kafkaComponentName(CLUSTER)));
        assertThat(ps.getMetadata().getLabels().entrySet().containsAll(spsLabels.entrySet()), is(true));
        assertThat(ps.getMetadata().getAnnotations().entrySet().containsAll(spsAnnos.entrySet()), is(true));
        assertThat(ps.getSpec().getSelector().getMatchLabels(), is(kc.getSelectorLabels().withStrimziPoolName("kafka").toMap()));
        assertThat(ps.getSpec().getPods().size(), is(3));

        // We need to loop through the pods to make sure they have the right values
        List<Pod> pods = PodSetUtils.podSetToPods(ps);
        for (Pod pod : pods)  {
            assertThat(pod.getMetadata().getLabels().entrySet().containsAll(podLabels.entrySet()), is(true));
            assertThat(pod.getMetadata().getAnnotations().entrySet().containsAll(podAnnos.entrySet()), is(true));
            assertThat(pod.getMetadata().getAnnotations().get("special"), is("annotation"));
            assertThat(pod.getSpec().getPriorityClassName(), is("top-priority"));
            assertThat(pod.getSpec().getSchedulerName(), is("my-scheduler"));
            assertThat(pod.getSpec().getHostAliases(), containsInAnyOrder(hostAlias1, hostAlias2));
            assertThat(pod.getSpec().getTopologySpreadConstraints(), containsInAnyOrder(tsc1, tsc2));
            assertThat(pod.getSpec().getEnableServiceLinks(), is(false));
            assertThat(pod.getSpec().getTerminationGracePeriodSeconds(), is(123L));
            assertThat(pod.getSpec().getVolumes().stream()
                    .filter(volume -> volume.getName().equalsIgnoreCase("strimzi-tmp"))
                    .findFirst().orElseThrow().getEmptyDir().getSizeLimit(), is(new Quantity("10Mi")));
            assertThat(pod.getSpec().getImagePullSecrets().size(), is(2));
            assertThat(pod.getSpec().getImagePullSecrets().contains(secret1), is(true));
            assertThat(pod.getSpec().getImagePullSecrets().contains(secret2), is(true));
            assertThat(pod.getSpec().getSecurityContext(), is(notNullValue()));
            assertThat(pod.getSpec().getSecurityContext().getFsGroup(), is(123L));
            assertThat(pod.getSpec().getSecurityContext().getRunAsGroup(), is(456L));
            assertThat(pod.getSpec().getSecurityContext().getRunAsUser(), is(789L));
            assertThat(pod.getSpec().getAffinity(), is(affinity));
            assertThat(pod.getSpec().getTolerations(), is(toleration));
            assertThat("Failed to correctly set container environment variable: " + testEnvOneKey,
                    pod.getSpec().getContainers().get(0).getEnv().stream().filter(env -> testEnvOneKey.equals(env.getName()))
                            .map(EnvVar::getValue).findFirst().orElse("").equals(testEnvOneValue), is(true));
            assertThat("Failed to correctly set container environment variable: " + testEnvTwoKey,
                    pod.getSpec().getContainers().get(0).getEnv().stream().filter(env -> testEnvTwoKey.equals(env.getName()))
                            .map(EnvVar::getValue).findFirst().orElse("").equals(testEnvTwoValue), is(true));
            assertThat(pod.getSpec().getContainers(),
                    hasItem(allOf(
                            hasProperty("name", equalTo(KafkaCluster.KAFKA_NAME)),
                            hasProperty("securityContext", equalTo(securityContext))
                    )));

            assertThat(pod.getSpec().getContainers().size(), is(1));
            assertThat(pod.getSpec().getContainers().get(0).getImage(), is(image));
            assertThat(pod.getSpec().getContainers().get(0).getLivenessProbe().getTimeoutSeconds(), is(livenessProbe.getTimeoutSeconds()));
            assertThat(pod.getSpec().getContainers().get(0).getLivenessProbe().getInitialDelaySeconds(), is(livenessProbe.getInitialDelaySeconds()));
            assertThat(pod.getSpec().getContainers().get(0).getLivenessProbe().getFailureThreshold(), is(livenessProbe.getFailureThreshold()));
            assertThat(pod.getSpec().getContainers().get(0).getLivenessProbe().getSuccessThreshold(), is(livenessProbe.getSuccessThreshold()));
            assertThat(pod.getSpec().getContainers().get(0).getLivenessProbe().getPeriodSeconds(), is(livenessProbe.getPeriodSeconds()));
            assertThat(pod.getSpec().getContainers().get(0).getReadinessProbe().getTimeoutSeconds(), is(readinessProbe.getTimeoutSeconds()));
            assertThat(pod.getSpec().getContainers().get(0).getReadinessProbe().getInitialDelaySeconds(), is(readinessProbe.getInitialDelaySeconds()));
            assertThat(pod.getSpec().getContainers().get(0).getReadinessProbe().getFailureThreshold(), is(readinessProbe.getFailureThreshold()));
            assertThat(pod.getSpec().getContainers().get(0).getReadinessProbe().getSuccessThreshold(), is(readinessProbe.getSuccessThreshold()));
            assertThat(pod.getSpec().getContainers().get(0).getReadinessProbe().getPeriodSeconds(), is(readinessProbe.getPeriodSeconds()));
            assertThat(io.strimzi.operator.cluster.TestUtils.containerEnvVars(pod.getSpec().getContainers().get(0)).get(AbstractModel.ENV_VAR_STRIMZI_KAFKA_GC_LOG_ENABLED), is("true"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(0).getName(), is("data-0"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(0).getMountPath(), is("/var/lib/kafka/data-0"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(1).getName(), is(VolumeUtils.STRIMZI_TMP_DIRECTORY_DEFAULT_VOLUME_NAME));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(1).getMountPath(), is(VolumeUtils.STRIMZI_TMP_DIRECTORY_DEFAULT_MOUNT_PATH));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(2).getName(), is(KafkaCluster.CLUSTER_CA_CERTS_VOLUME));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(2).getMountPath(), is(KafkaCluster.CLUSTER_CA_CERTS_VOLUME_MOUNT));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(3).getName(), is(KafkaCluster.BROKER_CERTS_VOLUME));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(3).getMountPath(), is(KafkaCluster.BROKER_CERTS_VOLUME_MOUNT));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(4).getName(), is(KafkaCluster.CLIENT_CA_CERTS_VOLUME));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(4).getMountPath(), is(KafkaCluster.CLIENT_CA_CERTS_VOLUME_MOUNT));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(5).getName(), is("kafka-metrics-and-logging"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(5).getMountPath(), is("/opt/kafka/custom-config/"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(6).getName(), is("ready-files"));
            assertThat(pod.getSpec().getContainers().get(0).getVolumeMounts().get(6).getMountPath(), is("/var/opt/kafka"));
        }
    }

    @ParallelTest
    public void testImagePullSecrets() {
        // CR configuration has priority -> CO configuration is ignored if both are set
        LocalObjectReference secret1 = new LocalObjectReference("some-pull-secret");
        LocalObjectReference secret2 = new LocalObjectReference("some-other-pull-secret");

        Kafka kafka = new KafkaBuilder(KAFKA)
                .editSpec()
                    .editKafka()
                        .withNewTemplate()
                            .withNewPod()
                                .withImagePullSecrets(secret1, secret2)
                            .endPod()
                        .endTemplate()
                    .endKafka()
                .endSpec()
                .build();

        List<KafkaPool> pools = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, kafka, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
        KafkaCluster kc = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kafka, pools, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);
        StrimziPodSet ps = kc.generatePodSets(true, null, null, brokerId -> new HashMap<>()).get(0);

        // We need to loop through the pods to make sure they have the right values
        List<Pod> pods = PodSetUtils.podSetToPods(ps);
        for (Pod pod : pods) {
            assertThat(pod.getSpec().getImagePullSecrets().size(), is(2));
            assertThat(pod.getSpec().getImagePullSecrets().contains(secret1), is(true));
            assertThat(pod.getSpec().getImagePullSecrets().contains(secret2), is(true));
        }
    }

    @ParallelTest
    public void testImagePullSecretsFromCO() {
        LocalObjectReference secret1 = new LocalObjectReference("some-pull-secret");
        LocalObjectReference secret2 = new LocalObjectReference("some-other-pull-secret");

        List<LocalObjectReference> secrets = new ArrayList<>(2);
        secrets.add(secret1);
        secrets.add(secret2);

        StrimziPodSet ps = KC.generatePodSets(true, null, secrets, brokerId -> new HashMap<>()).get(0);

        // We need to loop through the pods to make sure they have the right values
        List<Pod> pods = PodSetUtils.podSetToPods(ps);
        for (Pod pod : pods) {
            assertThat(pod.getSpec().getImagePullSecrets().size(), is(2));
            assertThat(pod.getSpec().getImagePullSecrets().contains(secret1), is(true));
            assertThat(pod.getSpec().getImagePullSecrets().contains(secret2), is(true));
        }
    }

    @ParallelTest
    public void testImagePullSecretsFromBoth() {
        // CR configuration has priority -> CO configuration is ignored if both are set
        LocalObjectReference secret1 = new LocalObjectReference("some-pull-secret");
        LocalObjectReference secret2 = new LocalObjectReference("some-other-pull-secret");

        Kafka kafka = new KafkaBuilder(KAFKA)
                .editSpec()
                    .editKafka()
                        .withNewTemplate()
                            .withNewPod()
                                .withImagePullSecrets(secret2)
                            .endPod()
                        .endTemplate()
                    .endKafka()
                .endSpec()
                .build();

        List<KafkaPool> pools = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, kafka, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
        KafkaCluster kc = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kafka, pools, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);
        StrimziPodSet ps = kc.generatePodSets(true, null, List.of(secret1), brokerId -> new HashMap<>()).get(0);

        // We need to loop through the pods to make sure they have the right values
        List<Pod> pods = PodSetUtils.podSetToPods(ps);
        for (Pod pod : pods) {
            assertThat(pod.getSpec().getImagePullSecrets().size(), is(1));
            assertThat(pod.getSpec().getImagePullSecrets().contains(secret1), is(false));
            assertThat(pod.getSpec().getImagePullSecrets().contains(secret2), is(true));
        }
    }

    @ParallelTest
    public void testDefaultImagePullSecrets() {
        StrimziPodSet ps = KC.generatePodSets(true, null, null, brokerId -> new HashMap<>()).get(0);

        // We need to loop through the pods to make sure they have the right values
        List<Pod> pods = PodSetUtils.podSetToPods(ps);
        for (Pod pod : pods) {
            assertThat(pod.getSpec().getImagePullSecrets().size(), is(0));
        }
    }

    @ParallelTest
    public void testImagePullPolicy() {
        // Test ALWAYS policy
        StrimziPodSet ps = KC.generatePodSets(true, ImagePullPolicy.ALWAYS, null, brokerId -> new HashMap<>()).get(0);

        // We need to loop through the pods to make sure they have the right values
        List<Pod> pods = PodSetUtils.podSetToPods(ps);
        for (Pod pod : pods) {
            assertThat(pod.getSpec().getContainers().get(0).getImagePullPolicy(), is(ImagePullPolicy.ALWAYS.toString()));
        }

        // Test IFNOTPRESENT policy
        ps = KC.generatePodSets(true, ImagePullPolicy.IFNOTPRESENT, null, brokerId -> new HashMap<>()).get(0);

        // We need to loop through the pods to make sure they have the right values
        pods = PodSetUtils.podSetToPods(ps);
        for (Pod pod : pods) {
            assertThat(pod.getSpec().getContainers().get(0).getImagePullPolicy(), is(ImagePullPolicy.IFNOTPRESENT.toString()));
        }
    }

    @ParallelTest
    public void testGeneratePodSetWithSetSizeLimit() {
        String sizeLimit = "1Gi";
        Kafka kafka = new KafkaBuilder(KAFKA)
                .editSpec()
                    .editKafka()
                        .withNewEphemeralStorage().withSizeLimit(sizeLimit).endEphemeralStorage()
                    .endKafka()
                .endSpec()
                .build();

        List<KafkaPool> pools = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, kafka, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
        KafkaCluster kc = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kafka, pools, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);

        // Test generated SPS
        StrimziPodSet ps = kc.generatePodSets(false, null, null, brokerId -> new HashMap<>()).get(0);
        List<Pod> pods = PodSetUtils.podSetToPods(ps);

        for (Pod pod : pods) {
            assertThat(pod.getSpec().getVolumes().get(0).getEmptyDir().getSizeLimit(), is(new Quantity("1", "Gi")));
        }
    }

    @ParallelTest
    public void testGeneratePodSetWithEmptySizeLimit() {
        Kafka kafka = new KafkaBuilder(KAFKA)
                .editSpec()
                    .editKafka()
                        .withNewEphemeralStorage().endEphemeralStorage()
                    .endKafka()
                .endSpec()
                .build();

        List<KafkaPool> pools = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, kafka, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
        KafkaCluster kc = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kafka, pools, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);

        // Test generated SPS
        StrimziPodSet ps = kc.generatePodSets(false, null, null, brokerId -> new HashMap<>()).get(0);
        List<Pod> pods = PodSetUtils.podSetToPods(ps);

        for (Pod pod : pods) {
            assertThat(pod.getSpec().getVolumes().get(0).getEmptyDir().getSizeLimit(), is(Matchers.nullValue()));
        }
    }

    @ParallelTest
    public void testEphemeralStorage()    {
        Kafka kafka = new KafkaBuilder(KAFKA)
                .editSpec()
                    .editKafka()
                        .withNewEphemeralStorage().endEphemeralStorage()
                    .endKafka()
                .endSpec()
                .build();

        List<KafkaPool> pools = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, kafka, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
        KafkaCluster kc = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kafka, pools, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);

        // Test generated SPS
        StrimziPodSet ps = kc.generatePodSets(false, null, null, brokerId -> new HashMap<>()).get(0);
        List<Pod> pods = PodSetUtils.podSetToPods(ps);

        for (Pod pod : pods) {
            assertThat(pod.getSpec().getVolumes().stream().filter(v -> "data".equals(v.getName())).findFirst().orElseThrow().getEmptyDir(), is(notNullValue()));
        }

        // Check PVCs
        List<PersistentVolumeClaim> pvcs = kc.generatePersistentVolumeClaims();
        assertThat(pvcs.size(), is(0));
    }

    @ParallelTest
    public void testRestrictedSecurityContext() {
        List<KafkaPool> pools = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, KAFKA, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
        KafkaCluster kc = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, KAFKA, pools, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);
        kc.securityProvider = new RestrictedPodSecurityProvider();
        kc.securityProvider.configure(new PlatformFeaturesAvailability(false, KubernetesVersion.MINIMAL_SUPPORTED_VERSION));

        // Test generated SPS
        StrimziPodSet ps = kc.generatePodSets(false, null, null, brokerId -> new HashMap<>()).get(0);
        List<Pod> pods = PodSetUtils.podSetToPods(ps);

        for (Pod pod : pods) {
            assertThat(pod.getSpec().getSecurityContext().getFsGroup(), is(0L));

            assertThat(pod.getSpec().getContainers().get(0).getSecurityContext().getAllowPrivilegeEscalation(), is(false));
            assertThat(pod.getSpec().getContainers().get(0).getSecurityContext().getRunAsNonRoot(), is(true));
            assertThat(pod.getSpec().getContainers().get(0).getSecurityContext().getSeccompProfile().getType(), is("RuntimeDefault"));
            assertThat(pod.getSpec().getContainers().get(0).getSecurityContext().getCapabilities().getDrop(), is(List.of("ALL")));
        }
    }

    @ParallelTest
    public void testCustomLabelsFromCR() {
        Kafka kafka = new KafkaBuilder(KAFKA)
                .editMetadata()
                    .addToLabels("foo", "bar")
                .endMetadata()
                .build();

        List<KafkaPool> pools = NodePoolUtils.createKafkaPools(Reconciliation.DUMMY_RECONCILIATION, kafka, null, Map.of(), Map.of(), false, SHARED_ENV_PROVIDER);
        KafkaCluster kc = KafkaCluster.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kafka, pools, VERSIONS, KafkaVersionTestUtils.DEFAULT_ZOOKEEPER_VERSION_CHANGE, KafkaMetadataConfigurationState.ZK, null, SHARED_ENV_PROVIDER);

        // Test generated SPS
        StrimziPodSet sps = kc.generatePodSets(false, null, null, brokerId -> new HashMap<>()).get(0);
        assertThat(sps.getMetadata().getLabels().get("foo"), is("bar"));

        List<Pod> pods = PodSetUtils.podSetToPods(sps);
        for (Pod pod : pods) {
            assertThat(pod.getMetadata().getLabels().get("foo"), is("bar"));
        }
    }

    @ParallelTest
    public void testDefaultSecurityContext() {
        StrimziPodSet sps = KC.generatePodSets(false, null, null, brokerId -> new HashMap<>()).get(0);

        List<Pod> pods = PodSetUtils.podSetToPods(sps);
        for (Pod pod : pods) {
            assertThat(pod.getSpec().getSecurityContext().getFsGroup(), is(0L));
            assertThat(pod.getSpec().getContainers().get(0).getSecurityContext(), is(nullValue()));
        }
    }
}
