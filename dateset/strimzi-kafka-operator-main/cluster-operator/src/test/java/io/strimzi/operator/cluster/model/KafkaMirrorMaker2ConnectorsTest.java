/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.model;

import io.strimzi.api.kafka.model.common.CertAndKeySecretSourceBuilder;
import io.strimzi.api.kafka.model.common.CertSecretSourceBuilder;
import io.strimzi.api.kafka.model.common.ConnectorState;
import io.strimzi.api.kafka.model.connector.KafkaConnector;
import io.strimzi.api.kafka.model.mirrormaker2.KafkaMirrorMaker2;
import io.strimzi.api.kafka.model.mirrormaker2.KafkaMirrorMaker2Builder;
import io.strimzi.api.kafka.model.mirrormaker2.KafkaMirrorMaker2ClusterSpec;
import io.strimzi.api.kafka.model.mirrormaker2.KafkaMirrorMaker2ClusterSpecBuilder;
import io.strimzi.api.kafka.model.mirrormaker2.KafkaMirrorMaker2MirrorSpec;
import io.strimzi.api.kafka.model.mirrormaker2.KafkaMirrorMaker2MirrorSpecBuilder;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.model.InvalidResourceException;
import org.junit.jupiter.api.Test;

import javax.security.auth.login.AppConfigurationEntry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("deprecation") // Uses deprecated getPause() field in tests
public class KafkaMirrorMaker2ConnectorsTest {
    private static final String PREFIX = "prefix.";

    private final static KafkaMirrorMaker2 KMM2 = new KafkaMirrorMaker2Builder()
            .withNewMetadata()
                .withName("my-mm2")
                .withNamespace("my-namespace")
            .endMetadata()
            .withNewSpec()
            .withReplicas(3)
            .withConnectCluster("target")
            .withClusters(new KafkaMirrorMaker2ClusterSpecBuilder()
                    .withAlias("source")
                    .withBootstrapServers("source:9092")
                    .build(),
                    new KafkaMirrorMaker2ClusterSpecBuilder()
                            .withAlias("target")
                            .withBootstrapServers("target:9092")
                            .build())
            .withMirrors(new KafkaMirrorMaker2MirrorSpecBuilder()
                    .withSourceCluster("source")
                    .withTargetCluster("target")
                    .withNewSourceConnector()
                        .withTasksMax(5)
                        .withConfig(Map.of("sync.topic.acls.enabled", "false"))
                    .endSourceConnector()
                    .withNewCheckpointConnector()
                        .withTasksMax(3)
                        .withConfig(Map.of("sync.group.offsets.enabled", "true"))
                    .endCheckpointConnector()
                    .withNewHeartbeatConnector()
                        .withTasksMax(1)
                    .endHeartbeatConnector()
                    .withTopicsPattern("my-topic-.*")
                    .withTopicsExcludePattern("exclude-topic-.*")
                    .withGroupsPattern("my-group-.*")
                    .withGroupsExcludePattern("exclude-group-.*")
                    .build())
            .endSpec()
            .build();

    @Test
    public void testValidation()    {
        assertDoesNotThrow(() -> KafkaMirrorMaker2Connectors.validateConnectors(KMM2));
    }

    @Test
    public void testFailingValidation()    {
        // Missing spec
        KafkaMirrorMaker2 kmm2WithoutSpec = new KafkaMirrorMaker2Builder(KMM2)
                .withSpec(null)
                .build();
        InvalidResourceException ex = assertThrows(InvalidResourceException.class, () -> KafkaMirrorMaker2Connectors.validateConnectors(kmm2WithoutSpec));
        assertThat(ex.getMessage(), is(".spec section is required for KafkaMirrorMaker2 resource"));

        // Missing clusters
        KafkaMirrorMaker2 kmm2WithoutClusters = new KafkaMirrorMaker2Builder(KMM2)
                .withNewSpec()
                    .withMirrors(List.of())
                .endSpec()
                .build();
        ex = assertThrows(InvalidResourceException.class, () -> KafkaMirrorMaker2Connectors.validateConnectors(kmm2WithoutClusters));
        assertThat(ex.getMessage(), is(".spec.clusters and .spec.mirrors sections are required in KafkaMirrorMaker2 resource"));

        // Missing mirrors
        KafkaMirrorMaker2 kmm2WithoutMirrors = new KafkaMirrorMaker2Builder(KMM2)
                .withNewSpec()
                    .withClusters(List.of())
                .endSpec()
                .build();
        ex = assertThrows(InvalidResourceException.class, () -> KafkaMirrorMaker2Connectors.validateConnectors(kmm2WithoutMirrors));
        assertThat(ex.getMessage(), is(".spec.clusters and .spec.mirrors sections are required in KafkaMirrorMaker2 resource"));

        // Missing alias
        KafkaMirrorMaker2 kmm2WrongAlias = new KafkaMirrorMaker2Builder(KMM2)
                .editSpec()
                    .editMirror(0)
                        .withSourceCluster(null)
                        .withTargetCluster("wrong-target")
                    .endMirror()
                .endSpec()
                .build();
        ex = assertThrows(InvalidResourceException.class, () -> KafkaMirrorMaker2Connectors.validateConnectors(kmm2WrongAlias));
        assertThat(ex.getMessage(), is("KafkaMirrorMaker2 resource validation failed: " +
                "[Each MirrorMaker 2 mirror definition has to specify the source cluster alias, " +
                "Target cluster alias wrong-target is used in a mirror definition, but cluster with this alias does not exist in cluster definitions]"));
    }

    @Test
    public void testConnectors() {
        KafkaMirrorMaker2Connectors connectors = KafkaMirrorMaker2Connectors.fromCrd(Reconciliation.DUMMY_RECONCILIATION, KMM2);
        List<KafkaConnector> kcs = connectors.generateConnectorDefinitions();

        Map<String, Object> expectedAll = new TreeMap<>();
        expectedAll.put("source.cluster.alias", "source");
        expectedAll.put("source.cluster.bootstrap.servers", "source:9092");
        expectedAll.put("source.cluster.security.protocol", "PLAINTEXT");
        expectedAll.put("target.cluster.alias", "target");
        expectedAll.put("target.cluster.bootstrap.servers", "target:9092");
        expectedAll.put("target.cluster.security.protocol", "PLAINTEXT");
        expectedAll.put("topics", "my-topic-.*");
        expectedAll.put("topics.exclude", "exclude-topic-.*");
        expectedAll.put("groups", "my-group-.*");
        expectedAll.put("groups.exclude", "exclude-group-.*");

        Map<String, Object> expectedSource = new TreeMap<>(expectedAll);
        expectedSource.put("sync.topic.acls.enabled", "false");

        Map<String, Object> expectedCheckpoint = new TreeMap<>(expectedAll);
        expectedCheckpoint.put("sync.group.offsets.enabled", "true");

        assertThat(kcs.size(), is(3));

        KafkaConnector kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorSourceConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorSourceConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorSourceConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(5));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedSource));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorCheckpointConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorCheckpointConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorCheckpointConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(3));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedCheckpoint));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorHeartbeatConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(1));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedAll));
    }

    @Test
    public void testConnectorsWithMultipleSources() {
        KafkaMirrorMaker2 kmm2 = new KafkaMirrorMaker2Builder(KMM2)
                .editSpec()
                    .addToClusters(new KafkaMirrorMaker2ClusterSpecBuilder()
                            .withAlias("other-source")
                            .withBootstrapServers("other-source:9092")
                            .build())
                    .addToMirrors(new KafkaMirrorMaker2MirrorSpecBuilder()
                            .withSourceCluster("other-source")
                            .withTargetCluster("target")
                            .withNewSourceConnector()
                                .withTasksMax(15)
                                .withConfig(Map.of("sync.topic.acls.enabled", "true"))
                            .endSourceConnector()
                            .withNewCheckpointConnector()
                                .withTasksMax(13)
                                .withConfig(Map.of("sync.group.offsets.enabled", "false"))
                            .endCheckpointConnector()
                            .withNewHeartbeatConnector()
                                .withTasksMax(11)
                            .endHeartbeatConnector()
                            .build())
                .endSpec()
                .build();

        KafkaMirrorMaker2Connectors connectors = KafkaMirrorMaker2Connectors.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kmm2);
        List<KafkaConnector> kcs = connectors.generateConnectorDefinitions();

        Map<String, Object> expectedAll = new TreeMap<>();
        expectedAll.put("source.cluster.alias", "source");
        expectedAll.put("source.cluster.bootstrap.servers", "source:9092");
        expectedAll.put("source.cluster.security.protocol", "PLAINTEXT");
        expectedAll.put("target.cluster.alias", "target");
        expectedAll.put("target.cluster.bootstrap.servers", "target:9092");
        expectedAll.put("target.cluster.security.protocol", "PLAINTEXT");
        expectedAll.put("topics", "my-topic-.*");
        expectedAll.put("topics.exclude", "exclude-topic-.*");
        expectedAll.put("groups", "my-group-.*");
        expectedAll.put("groups.exclude", "exclude-group-.*");

        Map<String, Object> expectedSource = new TreeMap<>(expectedAll);
        expectedSource.put("sync.topic.acls.enabled", "false");

        Map<String, Object> expectedCheckpoint = new TreeMap<>(expectedAll);
        expectedCheckpoint.put("sync.group.offsets.enabled", "true");

        Map<String, Object> expectedAll2 = new TreeMap<>();
        expectedAll2.put("source.cluster.alias", "other-source");
        expectedAll2.put("source.cluster.bootstrap.servers", "other-source:9092");
        expectedAll2.put("source.cluster.security.protocol", "PLAINTEXT");
        expectedAll2.put("target.cluster.alias", "target");
        expectedAll2.put("target.cluster.bootstrap.servers", "target:9092");
        expectedAll2.put("target.cluster.security.protocol", "PLAINTEXT");

        Map<String, Object> expectedSource2 = new TreeMap<>(expectedAll2);
        expectedSource2.put("sync.topic.acls.enabled", "true");

        Map<String, Object> expectedCheckpoint2 = new TreeMap<>(expectedAll2);
        expectedCheckpoint2.put("sync.group.offsets.enabled", "false");

        assertThat(kcs.size(), is(6));

        KafkaConnector kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorSourceConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorSourceConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorSourceConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(5));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedSource));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorCheckpointConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorCheckpointConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorCheckpointConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(3));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedCheckpoint));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorHeartbeatConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(1));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedAll));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("other-source->target.MirrorSourceConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("other-source->target.MirrorSourceConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorSourceConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(15));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedSource2));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("other-source->target.MirrorCheckpointConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("other-source->target.MirrorCheckpointConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorCheckpointConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(13));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedCheckpoint2));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("other-source->target.MirrorHeartbeatConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("other-source->target.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getTasksMax(), is(11));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(nullValue()));
        assertThat(kc.getSpec().getConfig(), is(expectedAll2));
    }

    @Test
    public void testConnectorsOnlySome() {
        KafkaMirrorMaker2 kmm2 = new KafkaMirrorMaker2Builder(KMM2)
                .editSpec()
                    .editMirror(0)
                        .withCheckpointConnector(null)
                    .endMirror()
                .endSpec()
                .build();

        KafkaMirrorMaker2Connectors connectors = KafkaMirrorMaker2Connectors.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kmm2);
        List<KafkaConnector> kcs = connectors.generateConnectorDefinitions();

        assertThat(kcs.size(), is(2));

        KafkaConnector kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorSourceConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorSourceConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorSourceConnector"));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorHeartbeatConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorHeartbeatConnector"));
    }

    @Test
    public void testConnectorsPauseState() {
        KafkaMirrorMaker2 kmm2 = new KafkaMirrorMaker2Builder(KMM2)
                .editSpec()
                    .editMirror(0)
                        .editSourceConnector()
                            .withState(ConnectorState.PAUSED)
                        .endSourceConnector()
                        .editCheckpointConnector()
                            .withPause(true)
                        .endCheckpointConnector()
                        .editHeartbeatConnector()
                            .withState(ConnectorState.STOPPED)
                            .withPause(true)
                        .endHeartbeatConnector()
                    .endMirror()
                .endSpec()
                .build();

        KafkaMirrorMaker2Connectors connectors = KafkaMirrorMaker2Connectors.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kmm2);
        List<KafkaConnector> kcs = connectors.generateConnectorDefinitions();

        assertThat(kcs.size(), is(3));

        KafkaConnector kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorSourceConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorSourceConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorSourceConnector"));
        assertThat(kc.getSpec().getPause(), is(nullValue()));
        assertThat(kc.getSpec().getState(), is(ConnectorState.PAUSED));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorCheckpointConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorCheckpointConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorCheckpointConnector"));
        assertThat(kc.getSpec().getPause(), is(true));
        assertThat(kc.getSpec().getState(), is(nullValue()));

        kc = kcs.stream().filter(k -> k.getMetadata().getName().contains("source->target.MirrorHeartbeatConnector")).findFirst().orElseThrow();
        assertThat(kc.getMetadata().getName(), is("source->target.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getClassName(), is("org.apache.kafka.connect.mirror.MirrorHeartbeatConnector"));
        assertThat(kc.getSpec().getPause(), is(true));
        assertThat(kc.getSpec().getState(), is(ConnectorState.STOPPED));
    }

    @Test
    public void testConnectorConfiguration() {
        KafkaMirrorMaker2Connectors connectors = KafkaMirrorMaker2Connectors.fromCrd(Reconciliation.DUMMY_RECONCILIATION, KMM2);
        Map<String, Object> config = connectors.prepareMirrorMaker2ConnectorConfig(KMM2.getSpec().getMirrors().get(0),
                KMM2.getSpec().getMirrors().get(0).getSourceConnector(),
                KMM2.getSpec().getClusters().get(0),
                KMM2.getSpec().getClusters().get(1));

        Map<String, Object> expected = new TreeMap<>();
        expected.put("source.cluster.alias", "source");
        expected.put("source.cluster.bootstrap.servers", "source:9092");
        expected.put("source.cluster.security.protocol", "PLAINTEXT");
        expected.put("target.cluster.alias", "target");
        expected.put("target.cluster.bootstrap.servers", "target:9092");
        expected.put("target.cluster.security.protocol", "PLAINTEXT");
        expected.put("sync.topic.acls.enabled", "false");
        expected.put("topics", "my-topic-.*");
        expected.put("topics.exclude", "exclude-topic-.*");
        expected.put("groups", "my-group-.*");
        expected.put("groups.exclude", "exclude-group-.*");

        assertThat(new TreeMap<>(config), is(expected));
    }

    @Test
    public void testConnectorConfigurationAlsoWithDeprecatedFields() {
        KafkaMirrorMaker2MirrorSpec mirror = new KafkaMirrorMaker2MirrorSpecBuilder(KMM2.getSpec().getMirrors().get(0))
                .withGroupsBlacklistPattern("other-group-.*")
                .withTopicsBlacklistPattern("other-topic-.*")

                .build();

        KafkaMirrorMaker2Connectors connectors = KafkaMirrorMaker2Connectors.fromCrd(Reconciliation.DUMMY_RECONCILIATION, KMM2);
        Map<String, Object> config = connectors.prepareMirrorMaker2ConnectorConfig(mirror,
                KMM2.getSpec().getMirrors().get(0).getSourceConnector(),
                KMM2.getSpec().getClusters().get(0),
                KMM2.getSpec().getClusters().get(1));

        Map<String, Object> expected = new TreeMap<>();
        expected.put("source.cluster.alias", "source");
        expected.put("source.cluster.bootstrap.servers", "source:9092");
        expected.put("source.cluster.security.protocol", "PLAINTEXT");
        expected.put("target.cluster.alias", "target");
        expected.put("target.cluster.bootstrap.servers", "target:9092");
        expected.put("target.cluster.security.protocol", "PLAINTEXT");
        expected.put("sync.topic.acls.enabled", "false");
        expected.put("topics", "my-topic-.*");
        expected.put("topics.exclude", "exclude-topic-.*");
        expected.put("groups", "my-group-.*");
        expected.put("groups.exclude", "exclude-group-.*");

        assertThat(new TreeMap<>(config), is(expected));
    }

    @Test
    public void testConnectorConfigurationOnlyWithDeprecatedFields() {
        KafkaMirrorMaker2MirrorSpec mirror = new KafkaMirrorMaker2MirrorSpecBuilder(KMM2.getSpec().getMirrors().get(0))
                .withGroupsBlacklistPattern("other-group-.*")
                .withTopicsBlacklistPattern("other-topic-.*")
                .withTopicsExcludePattern(null)
                .withGroupsExcludePattern(null)
                .build();

        KafkaMirrorMaker2Connectors connectors = KafkaMirrorMaker2Connectors.fromCrd(Reconciliation.DUMMY_RECONCILIATION, KMM2);
        Map<String, Object> config = connectors.prepareMirrorMaker2ConnectorConfig(mirror,
                KMM2.getSpec().getMirrors().get(0).getSourceConnector(),
                KMM2.getSpec().getClusters().get(0),
                KMM2.getSpec().getClusters().get(1));

        Map<String, Object> expected = new TreeMap<>();
        expected.put("source.cluster.alias", "source");
        expected.put("source.cluster.bootstrap.servers", "source:9092");
        expected.put("source.cluster.security.protocol", "PLAINTEXT");
        expected.put("target.cluster.alias", "target");
        expected.put("target.cluster.bootstrap.servers", "target:9092");
        expected.put("target.cluster.security.protocol", "PLAINTEXT");
        expected.put("sync.topic.acls.enabled", "false");
        expected.put("topics", "my-topic-.*");
        expected.put("topics.exclude", "other-topic-.*");
        expected.put("groups", "my-group-.*");
        expected.put("groups.exclude", "other-group-.*");

        assertThat(new TreeMap<>(config), is(expected));
    }

    @Test
    public void testConnectorConfigurationOnlyWithRackAndTracing() {
        KafkaMirrorMaker2 kmm2 = new KafkaMirrorMaker2Builder(KMM2)
                .editSpec()
                .withNewRack()
                    .withTopologyKey("my-topology-key")
                .endRack()
                .withNewOpenTelemetryTracing()
                .endOpenTelemetryTracing()
                .endSpec()
                .build();

        KafkaMirrorMaker2Connectors connectors = KafkaMirrorMaker2Connectors.fromCrd(Reconciliation.DUMMY_RECONCILIATION, kmm2);
        Map<String, Object> config = connectors.prepareMirrorMaker2ConnectorConfig(KMM2.getSpec().getMirrors().get(0),
                KMM2.getSpec().getMirrors().get(0).getSourceConnector(),
                KMM2.getSpec().getClusters().get(0),
                KMM2.getSpec().getClusters().get(1));

        Map<String, Object> expected = new TreeMap<>();
        expected.put("source.cluster.alias", "source");
        expected.put("source.cluster.bootstrap.servers", "source:9092");
        expected.put("source.cluster.security.protocol", "PLAINTEXT");
        expected.put("target.cluster.alias", "target");
        expected.put("target.cluster.bootstrap.servers", "target:9092");
        expected.put("target.cluster.security.protocol", "PLAINTEXT");
        expected.put("sync.topic.acls.enabled", "false");
        expected.put("topics", "my-topic-.*");
        expected.put("topics.exclude", "exclude-topic-.*");
        expected.put("groups", "my-group-.*");
        expected.put("groups.exclude", "exclude-group-.*");
        expected.put("consumer.client.rack", "${file:/tmp/strimzi-connect.properties:consumer.client.rack}");
        expected.put("consumer.interceptor.classes", "io.opentelemetry.instrumentation.kafkaclients.v2_6.TracingConsumerInterceptor");
        expected.put("producer.interceptor.classes", "io.opentelemetry.instrumentation.kafkaclients.v2_6.TracingProducerInterceptor");

        assertThat(new TreeMap<>(config), is(expected));
    }

    @Test
    public void testAddClusterToMirrorMaker2ConnectorConfigWithoutAuth() {
        Map<String, Object> config = new HashMap<>();
        KafkaMirrorMaker2ClusterSpec cluster = new KafkaMirrorMaker2ClusterSpecBuilder()
                .withAlias("sourceClusterAlias")
                .withBootstrapServers("sourceClusterAlias.sourceNamespace.svc:9092")
                .build();

        KafkaMirrorMaker2Connectors.addClusterToMirrorMaker2ConnectorConfig(config, cluster, PREFIX);

        assertThat(new TreeMap<>(config),
                is(new TreeMap<>(Map.of("prefix.alias", "sourceClusterAlias",
                                "prefix.security.protocol", "PLAINTEXT",
                                "prefix.bootstrap.servers", "sourceClusterAlias.sourceNamespace.svc:9092"))));
    }

    @Test
    public void testAddClusterToMirrorMaker2ConnectorConfigWithoutAuthWithClusterConfig() {
        Map<String, Object> config = new HashMap<>();
        KafkaMirrorMaker2ClusterSpec cluster = new KafkaMirrorMaker2ClusterSpecBuilder()
                .withAlias("sourceClusterAlias")
                .withBootstrapServers("sourceClusterAlias.sourceNamespace.svc:9092")
                .withConfig(Map.of("config.storage.replication.factor", "-1"))
                .build();

        KafkaMirrorMaker2Connectors.addClusterToMirrorMaker2ConnectorConfig(config, cluster, PREFIX);

        assertThat(new TreeMap<>(config),
                is(new TreeMap<>(Map.of("prefix.alias", "sourceClusterAlias",
                                "prefix.security.protocol", "PLAINTEXT",
                                "prefix.bootstrap.servers", "sourceClusterAlias.sourceNamespace.svc:9092",
                                "prefix.config.storage.replication.factor", "-1"))));
    }

    @Test
    public void testAddClusterToMirrorMaker2ConnectorConfigWithTlsAuth() {
        Map<String, Object> config = new HashMap<>();
        KafkaMirrorMaker2ClusterSpec cluster = new KafkaMirrorMaker2ClusterSpecBuilder()
                .withAlias("sourceClusterAlias")
                .withBootstrapServers("sourceClusterAlias.sourceNamespace.svc:9092")
                .withNewKafkaClientAuthenticationTls()
                    .withNewCertificateAndKey()
                        .withSecretName("my-secret")
                        .withCertificate("my.crt")
                        .withKey("my.key")
                    .endCertificateAndKey()
                .endKafkaClientAuthenticationTls()
                .withNewTls()
                .endTls()
                .build();

        KafkaMirrorMaker2Connectors.addClusterToMirrorMaker2ConnectorConfig(config, cluster, PREFIX);

        assertThat(config.containsKey("prefix.sasl.jaas.config"), is(false));
        assertThat(new TreeMap<>(config),
                is(new TreeMap<>(Map.of("prefix.alias", "sourceClusterAlias",
                                "prefix.security.protocol", "SSL",
                                "prefix.ssl.keystore.location", "/tmp/kafka/clusters/sourceClusterAlias.keystore.p12",
                                "prefix.ssl.keystore.password", "${file:/tmp/strimzi-mirrormaker2-connector.properties:ssl.keystore.password}",
                                "prefix.ssl.keystore.type", "PKCS12",
                                "prefix.bootstrap.servers", "sourceClusterAlias.sourceNamespace.svc:9092"))));
    }

    @Test
    public void testAddClusterToMirrorMaker2ConnectorConfigWithPlain() {
        Map<String, Object> config = new HashMap<>();
        KafkaMirrorMaker2ClusterSpec cluster = new KafkaMirrorMaker2ClusterSpecBuilder()
                .withAlias("sourceClusterAlias")
                .withBootstrapServers("sourceClusterAlias.sourceNamespace.svc:9092")
                .withNewKafkaClientAuthenticationPlain()
                    .withUsername("shaza")
                    .withNewPasswordSecret()
                        .withPassword("pa55word")
                    .endPasswordSecret()
                    .endKafkaClientAuthenticationPlain()
                .build();

        KafkaMirrorMaker2Connectors.addClusterToMirrorMaker2ConnectorConfig(config, cluster, PREFIX);

        String jaasConfig = (String) config.remove("prefix.sasl.jaas.config");
        AppConfigurationEntry configEntry = AuthenticationUtilsTest.parseJaasConfig(jaasConfig);
        assertThat(configEntry.getLoginModuleName(), is("org.apache.kafka.common.security.plain.PlainLoginModule"));
        assertThat(configEntry.getOptions(),
                is(Map.of("username", "shaza",
                        "password", "${file:/tmp/strimzi-mirrormaker2-connector.properties:sourceClusterAlias.sasl.password}")));

        assertThat(new TreeMap<>(config),
                is(new TreeMap<>(Map.of("prefix.alias", "sourceClusterAlias",
                        "prefix.security.protocol", "SASL_PLAINTEXT",
                        "prefix.sasl.mechanism", "PLAIN",
                        "prefix.bootstrap.servers", "sourceClusterAlias.sourceNamespace.svc:9092"))));
    }

    @Test
    public void testAddClusterToMirrorMaker2ConnectorConfigWithScram() {
        Map<String, Object> config = new HashMap<>();
        KafkaMirrorMaker2ClusterSpec cluster = new KafkaMirrorMaker2ClusterSpecBuilder()
                .withAlias("sourceClusterAlias")
                .withBootstrapServers("sourceClusterAlias.sourceNamespace.svc:9092")
                .withNewKafkaClientAuthenticationScramSha512()
                    .withUsername("shaza")
                    .withNewPasswordSecret()
                        .withPassword("pa55word")
                    .endPasswordSecret()
                .endKafkaClientAuthenticationScramSha512()
                .build();

        KafkaMirrorMaker2Connectors.addClusterToMirrorMaker2ConnectorConfig(config, cluster, PREFIX);

        String jaasConfig = (String) config.remove("prefix.sasl.jaas.config");
        AppConfigurationEntry configEntry = AuthenticationUtilsTest.parseJaasConfig(jaasConfig);
        assertThat(configEntry.getLoginModuleName(), is("org.apache.kafka.common.security.scram.ScramLoginModule"));
        assertThat(configEntry.getOptions(),
                is(Map.of("username", "shaza",
                        "password", "${file:/tmp/strimzi-mirrormaker2-connector.properties:sourceClusterAlias.sasl.password}")));

        assertThat(new TreeMap<>(config),
                is(new TreeMap<>(Map.of("prefix.alias", "sourceClusterAlias",
                        "prefix.security.protocol", "SASL_PLAINTEXT",
                        "prefix.sasl.mechanism", "SCRAM-SHA-512",
                        "prefix.bootstrap.servers", "sourceClusterAlias.sourceNamespace.svc:9092"))));
    }

    @Test
    public void testAddClusterToMirrorMaker2ConnectorConfigWithOauth() {
        Map<String, Object> config = new HashMap<>();
        KafkaMirrorMaker2ClusterSpec cluster = new KafkaMirrorMaker2ClusterSpecBuilder()
                .withAlias("sourceClusterAlias")
                .withBootstrapServers("sourceClusterAlias.sourceNamespace.svc:9092")
                .withNewKafkaClientAuthenticationOAuth()
                    .withNewAccessToken()
                        .withKey("accessTokenKey")
                        .withSecretName("accessTokenSecretName")
                    .endAccessToken()
                    .withNewClientSecret()
                        .withKey("clientSecretKey")
                        .withSecretName("clientSecretSecretName")
                    .endClientSecret()
                    .withNewPasswordSecret()
                        .withPassword("passwordSecretPassword")
                        .withSecretName("passwordSecretSecretName")
                    .endPasswordSecret()
                    .withNewRefreshToken()
                        .withKey("refreshTokenKey")
                        .withSecretName("refreshTokenSecretName")
                    .endRefreshToken()
                    .withTlsTrustedCertificates(new CertSecretSourceBuilder().withCertificate("ca.crt").withSecretName("my-oauth-secret").build())
                .endKafkaClientAuthenticationOAuth()
                .build();

        KafkaMirrorMaker2Connectors.addClusterToMirrorMaker2ConnectorConfig(config, cluster, PREFIX);

        String jaasConfig = (String) config.remove("prefix.sasl.jaas.config");
        AppConfigurationEntry configEntry = AuthenticationUtilsTest.parseJaasConfig(jaasConfig);
        assertThat(configEntry.getLoginModuleName(), is("org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule"));
        assertThat(configEntry.getOptions(),
                is(Map.of("oauth.client.secret", "${file:/tmp/strimzi-mirrormaker2-connector.properties:sourceClusterAlias.oauth.client.secret}",
                        "oauth.access.token", "${file:/tmp/strimzi-mirrormaker2-connector.properties:sourceClusterAlias.oauth.access.token}",
                        "oauth.refresh.token", "${file:/tmp/strimzi-mirrormaker2-connector.properties:sourceClusterAlias.oauth.refresh.token}",
                        "oauth.password.grant.password", "${file:/tmp/strimzi-mirrormaker2-connector.properties:sourceClusterAlias.oauth.password.grant.password}",
                        "oauth.ssl.truststore.location", "/tmp/kafka/clusters/sourceClusterAlias-oauth.truststore.p12",
                        "oauth.ssl.truststore.type", "PKCS12",
                        "oauth.ssl.truststore.password", "${file:/tmp/strimzi-mirrormaker2-connector.properties:oauth.ssl.truststore.password}")));

        assertThat(config,
                is(Map.of("prefix.alias", "sourceClusterAlias",
                        "prefix.bootstrap.servers", "sourceClusterAlias.sourceNamespace.svc:9092",
                        "prefix.sasl.login.callback.handler.class", "io.strimzi.kafka.oauth.client.JaasClientOauthLoginCallbackHandler",
                        "prefix.sasl.mechanism", "OAUTHBEARER",
                        "prefix.security.protocol", "SASL_PLAINTEXT")));
    }

    @Test
    public void testAddClusterToMirrorMaker2ConnectorConfigWithScramAndTlsEncryption() {
        Map<String, Object> config = new HashMap<>();
        KafkaMirrorMaker2ClusterSpec cluster = new KafkaMirrorMaker2ClusterSpecBuilder()
                .withAlias("sourceClusterAlias")
                .withBootstrapServers("sourceClusterAlias.sourceNamespace.svc:9092")
                .withNewKafkaClientAuthenticationScramSha512()
                    .withUsername("shaza")
                    .withNewPasswordSecret()
                        .withPassword("pa55word")
                    .endPasswordSecret()
                .endKafkaClientAuthenticationScramSha512()
                .withNewTls()
                    .withTrustedCertificates(new CertAndKeySecretSourceBuilder().withSecretName("my-tls").withCertificate("ca.crt").build())
                .endTls()
                .build();

        KafkaMirrorMaker2Connectors.addClusterToMirrorMaker2ConnectorConfig(config, cluster, PREFIX);

        String jaasConfig = (String) config.remove("prefix.sasl.jaas.config");
        AppConfigurationEntry configEntry = AuthenticationUtilsTest.parseJaasConfig(jaasConfig);
        assertThat("org.apache.kafka.common.security.scram.ScramLoginModule", is(configEntry.getLoginModuleName()));
        assertThat(configEntry.getOptions(),
                is(Map.of("username", "shaza",
                        "password", "${file:/tmp/strimzi-mirrormaker2-connector.properties:sourceClusterAlias.sasl.password}")));

        assertThat(new TreeMap<>(config),
                is(new TreeMap<>(Map.of("prefix.alias", "sourceClusterAlias",
                        "prefix.security.protocol", "SASL_SSL",
                       "prefix.ssl.truststore.location", "/tmp/kafka/clusters/sourceClusterAlias.truststore.p12",
                       "prefix.ssl.truststore.password", "${file:/tmp/strimzi-mirrormaker2-connector.properties:ssl.truststore.password}",
                        "prefix.ssl.truststore.type", "PKCS12",
                        "prefix.sasl.mechanism", "SCRAM-SHA-512",
                        "prefix.bootstrap.servers", "sourceClusterAlias.sourceNamespace.svc:9092"))));
    }
}
