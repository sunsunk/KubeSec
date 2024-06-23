/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.api.kafka;

import io.fabric8.kubernetes.api.model.DefaultKubernetesResourceList;
import io.fabric8.kubernetes.api.model.apiextensions.v1.CustomResourceDefinition;
import io.fabric8.kubernetes.api.model.apiextensions.v1.CustomResourceDefinitionBuilder;
import io.fabric8.kubernetes.api.model.apiextensions.v1.CustomResourceDefinitionVersion;
import io.fabric8.kubernetes.api.model.apiextensions.v1.CustomResourceDefinitionVersionBuilder;
import io.fabric8.kubernetes.api.model.apiextensions.v1.CustomResourceSubresourceStatus;
import io.fabric8.kubernetes.client.CustomResource;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.strimzi.api.kafka.model.bridge.KafkaBridge;
import io.strimzi.api.kafka.model.bridge.KafkaBridgeList;
import io.strimzi.api.kafka.model.connect.KafkaConnect;
import io.strimzi.api.kafka.model.connect.KafkaConnectList;
import io.strimzi.api.kafka.model.connector.KafkaConnector;
import io.strimzi.api.kafka.model.connector.KafkaConnectorList;
import io.strimzi.api.kafka.model.kafka.Kafka;
import io.strimzi.api.kafka.model.kafka.KafkaList;
import io.strimzi.api.kafka.model.mirrormaker.KafkaMirrorMaker;
import io.strimzi.api.kafka.model.mirrormaker.KafkaMirrorMakerList;
import io.strimzi.api.kafka.model.mirrormaker2.KafkaMirrorMaker2;
import io.strimzi.api.kafka.model.mirrormaker2.KafkaMirrorMaker2List;
import io.strimzi.api.kafka.model.nodepool.KafkaNodePool;
import io.strimzi.api.kafka.model.nodepool.KafkaNodePoolList;
import io.strimzi.api.kafka.model.podset.StrimziPodSet;
import io.strimzi.api.kafka.model.podset.StrimziPodSetList;
import io.strimzi.api.kafka.model.rebalance.KafkaRebalance;
import io.strimzi.api.kafka.model.rebalance.KafkaRebalanceList;
import io.strimzi.api.kafka.model.topic.KafkaTopic;
import io.strimzi.api.kafka.model.topic.KafkaTopicList;
import io.strimzi.api.kafka.model.user.KafkaUser;
import io.strimzi.api.kafka.model.user.KafkaUserList;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;

/**
 * "Static" information about the CRDs defined in this package
 */
@SuppressWarnings("deprecation") // Kafka Mirror Maker is deprecated
public class Crds {
    @SuppressWarnings("unchecked")
    private static final Class<? extends CustomResource>[] CRDS = new Class[] {
        Kafka.class,
        KafkaConnect.class,
        KafkaTopic.class,
        KafkaUser.class,
        KafkaMirrorMaker.class,
        KafkaBridge.class,
        KafkaConnector.class,
        KafkaMirrorMaker2.class,
        KafkaRebalance.class,
        StrimziPodSet.class,
        KafkaNodePool.class
    };

    private Crds() {
    }

    @SuppressWarnings({"checkstyle:JavaNCSS"})
    private static CustomResourceDefinition crd(Class<? extends CustomResource> cls) {
        String scope, plural, singular, group, kind, listKind;
        List<String> versions;
        CustomResourceSubresourceStatus status = null;

        if (cls.equals(Kafka.class)) {
            scope = Kafka.SCOPE;
            plural = Kafka.RESOURCE_PLURAL;
            singular = Kafka.RESOURCE_SINGULAR;
            group = Kafka.RESOURCE_GROUP;
            kind = Kafka.RESOURCE_KIND;
            listKind = Kafka.RESOURCE_LIST_KIND;
            versions = Kafka.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(KafkaConnect.class)) {
            scope = KafkaConnect.SCOPE;
            plural = KafkaConnect.RESOURCE_PLURAL;
            singular = KafkaConnect.RESOURCE_SINGULAR;
            group = KafkaConnect.RESOURCE_GROUP;
            kind = KafkaConnect.RESOURCE_KIND;
            listKind = KafkaConnect.RESOURCE_LIST_KIND;
            versions = KafkaConnect.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(KafkaTopic.class)) {
            scope = KafkaTopic.SCOPE;
            plural = KafkaTopic.RESOURCE_PLURAL;
            singular = KafkaTopic.RESOURCE_SINGULAR;
            group = KafkaTopic.RESOURCE_GROUP;
            kind = KafkaTopic.RESOURCE_KIND;
            listKind = KafkaTopic.RESOURCE_LIST_KIND;
            versions = KafkaTopic.VERSIONS;
        } else if (cls.equals(KafkaUser.class)) {
            scope = KafkaUser.SCOPE;
            plural = KafkaUser.RESOURCE_PLURAL;
            singular = KafkaUser.RESOURCE_SINGULAR;
            group = KafkaUser.RESOURCE_GROUP;
            kind = KafkaUser.RESOURCE_KIND;
            listKind = KafkaUser.RESOURCE_LIST_KIND;
            versions = KafkaUser.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(KafkaMirrorMaker.class)) {
            scope = KafkaMirrorMaker.SCOPE;
            plural = KafkaMirrorMaker.RESOURCE_PLURAL;
            singular = KafkaMirrorMaker.RESOURCE_SINGULAR;
            group = KafkaMirrorMaker.RESOURCE_GROUP;
            kind = KafkaMirrorMaker.RESOURCE_KIND;
            listKind = KafkaMirrorMaker.RESOURCE_LIST_KIND;
            versions = KafkaMirrorMaker.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(KafkaBridge.class)) {
            scope = KafkaBridge.SCOPE;
            plural = KafkaBridge.RESOURCE_PLURAL;
            singular = KafkaBridge.RESOURCE_SINGULAR;
            group = KafkaBridge.RESOURCE_GROUP;
            kind = KafkaBridge.RESOURCE_KIND;
            listKind = KafkaBridge.RESOURCE_LIST_KIND;
            versions = KafkaBridge.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(KafkaConnector.class)) {
            scope = KafkaConnector.SCOPE;
            plural = KafkaConnector.RESOURCE_PLURAL;
            singular = KafkaConnector.RESOURCE_SINGULAR;
            group = KafkaConnector.RESOURCE_GROUP;
            kind = KafkaConnector.RESOURCE_KIND;
            listKind = KafkaConnector.RESOURCE_LIST_KIND;
            versions = KafkaConnector.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(KafkaMirrorMaker2.class)) {
            scope = KafkaMirrorMaker2.SCOPE;
            plural = KafkaMirrorMaker2.RESOURCE_PLURAL;
            singular = KafkaMirrorMaker2.RESOURCE_SINGULAR;
            group = KafkaMirrorMaker2.RESOURCE_GROUP;
            kind = KafkaMirrorMaker2.RESOURCE_KIND;
            listKind = KafkaMirrorMaker2.RESOURCE_LIST_KIND;
            versions = KafkaMirrorMaker2.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(KafkaRebalance.class)) {
            scope = KafkaRebalance.SCOPE;
            plural = KafkaRebalance.RESOURCE_PLURAL;
            singular = KafkaRebalance.RESOURCE_SINGULAR;
            group = KafkaRebalance.RESOURCE_GROUP;
            kind = KafkaRebalance.RESOURCE_KIND;
            listKind = KafkaRebalance.RESOURCE_LIST_KIND;
            versions = KafkaRebalance.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(StrimziPodSet.class)) {
            scope = StrimziPodSet.SCOPE;
            plural = StrimziPodSet.RESOURCE_PLURAL;
            singular = StrimziPodSet.RESOURCE_SINGULAR;
            group = StrimziPodSet.RESOURCE_GROUP;
            kind = StrimziPodSet.RESOURCE_KIND;
            listKind = StrimziPodSet.RESOURCE_LIST_KIND;
            versions = StrimziPodSet.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else if (cls.equals(KafkaNodePool.class)) {
            scope = KafkaNodePool.SCOPE;
            plural = KafkaNodePool.RESOURCE_PLURAL;
            singular = KafkaNodePool.RESOURCE_SINGULAR;
            group = KafkaNodePool.RESOURCE_GROUP;
            kind = KafkaNodePool.RESOURCE_KIND;
            listKind = KafkaNodePool.RESOURCE_LIST_KIND;
            versions = KafkaNodePool.VERSIONS;
            status = new CustomResourceSubresourceStatus();
        } else {
            throw new RuntimeException();
        }

        List<CustomResourceDefinitionVersion> crVersions = new ArrayList<>(versions.size());
        for (String apiVersion : versions)  {
            crVersions.add(new CustomResourceDefinitionVersionBuilder()
                    .withName(apiVersion)
                    .withNewSubresources()
                        .withStatus(status)
                    .endSubresources()
                    .withNewSchema()
                        .withNewOpenAPIV3Schema()
                            .withType("object")
                            .withXKubernetesPreserveUnknownFields(true)
                        .endOpenAPIV3Schema()
                    .endSchema()
                    .withStorage("v1beta2".equals(apiVersion))
                    .withServed(true)
                    .build());
        }

        return new CustomResourceDefinitionBuilder()
                .withNewMetadata()
                    .withName(plural + "." + group)
                .endMetadata()
                .withNewSpec()
                    .withScope(scope)
                    .withGroup(group)
                    .withVersions(crVersions)
                    .withNewNames()
                        .withSingular(singular)
                        .withPlural(plural)
                        .withKind(kind)
                        .withListKind(listKind)
                    .endNames()
                .endSpec()
                .build();
    }

    public static CustomResourceDefinition kafka() {
        return crd(Kafka.class);
    }

    public static MixedOperation<Kafka, KafkaList, Resource<Kafka>> kafkaOperation(KubernetesClient client) {
        return client.resources(Kafka.class, KafkaList.class);
    }

    public static CustomResourceDefinition kafkaConnect() {
        return crd(KafkaConnect.class);
    }

    public static MixedOperation<KafkaConnect, KafkaConnectList, Resource<KafkaConnect>> kafkaConnectOperation(KubernetesClient client) {
        return client.resources(KafkaConnect.class, KafkaConnectList.class);
    }

    public static CustomResourceDefinition kafkaConnector() {
        return crd(KafkaConnector.class);
    }

    public static MixedOperation<KafkaConnector, KafkaConnectorList, Resource<KafkaConnector>> kafkaConnectorOperation(KubernetesClient client) {
        return client.resources(KafkaConnector.class, KafkaConnectorList.class);
    }

    public static CustomResourceDefinition kafkaTopic() {
        return crd(KafkaTopic.class);
    }

    public static MixedOperation<KafkaTopic, KafkaTopicList, Resource<KafkaTopic>> topicOperation(KubernetesClient client) {
        return client.resources(KafkaTopic.class, KafkaTopicList.class);
    }

    public static CustomResourceDefinition kafkaUser() {
        return crd(KafkaUser.class);
    }

    public static MixedOperation<KafkaUser, KafkaUserList, Resource<KafkaUser>> kafkaUserOperation(KubernetesClient client) {
        return client.resources(KafkaUser.class, KafkaUserList.class);
    }

    public static CustomResourceDefinition kafkaMirrorMaker() {
        return crd(KafkaMirrorMaker.class);
    }

    public static MixedOperation<KafkaMirrorMaker, KafkaMirrorMakerList, Resource<KafkaMirrorMaker>> mirrorMakerOperation(KubernetesClient client) {
        return client.resources(KafkaMirrorMaker.class, KafkaMirrorMakerList.class);
    }

    public static CustomResourceDefinition kafkaBridge() {
        return crd(KafkaBridge.class);
    }

    public static MixedOperation<KafkaBridge, KafkaBridgeList, Resource<KafkaBridge>> kafkaBridgeOperation(KubernetesClient client) {
        return client.resources(KafkaBridge.class, KafkaBridgeList.class);
    }

    public static CustomResourceDefinition kafkaMirrorMaker2() {
        return crd(KafkaMirrorMaker2.class);
    }

    public static MixedOperation<KafkaMirrorMaker2, KafkaMirrorMaker2List, Resource<KafkaMirrorMaker2>> kafkaMirrorMaker2Operation(KubernetesClient client) {
        return client.resources(KafkaMirrorMaker2.class, KafkaMirrorMaker2List.class);
    }

    public static CustomResourceDefinition kafkaRebalance() {
        return crd(KafkaRebalance.class);
    }

    public static MixedOperation<KafkaRebalance, KafkaRebalanceList, Resource<KafkaRebalance>> kafkaRebalanceOperation(KubernetesClient client) {
        return client.resources(KafkaRebalance.class, KafkaRebalanceList.class);
    }

    public static CustomResourceDefinition strimziPodSet() {
        return crd(StrimziPodSet.class);
    }

    public static MixedOperation<StrimziPodSet, StrimziPodSetList, Resource<StrimziPodSet>> strimziPodSetOperation(KubernetesClient client) {
        return client.resources(StrimziPodSet.class, StrimziPodSetList.class);
    }

    public static CustomResourceDefinition kafkaNodePool() {
        return crd(KafkaNodePool.class);
    }

    public static MixedOperation<KafkaNodePool, KafkaNodePoolList, Resource<KafkaNodePool>> kafkaNodePoolOperation(KubernetesClient client) {
        return client.resources(KafkaNodePool.class, KafkaNodePoolList.class);
    }

    public static <T extends CustomResource, L extends DefaultKubernetesResourceList<T>> MixedOperation<T, L, Resource<T>>
            operation(KubernetesClient client,
                      Class<T> cls,
                      Class<L> listCls) {
        return client.resources(cls, listCls);
    }

    public static <T extends CustomResource> String kind(Class<T> cls) {
        try {
            return cls.getDeclaredConstructor().newInstance().getKind();
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T extends CustomResource> List<String> apiVersions(Class<T> cls) {
        try {
            String group = (String) cls.getField("RESOURCE_GROUP").get(null);

            List<String> versions;
            try {
                versions = singletonList(group + "/" + (String) cls.getField("VERSION").get(null));
            } catch (NoSuchFieldException e) {
                versions = ((List<String>) cls.getField("VERSIONS").get(null)).stream().map(v ->
                        group + "/" + v).collect(Collectors.toList());
            }
            return versions;
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public static int getNumCrds() {
        return CRDS.length;
    }
}
