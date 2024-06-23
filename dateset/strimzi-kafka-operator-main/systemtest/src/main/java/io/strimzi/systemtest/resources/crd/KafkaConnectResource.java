/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.systemtest.resources.crd;

import io.fabric8.kubernetes.api.model.DeletionPropagation;
import io.fabric8.kubernetes.api.model.LabelSelector;
import io.fabric8.kubernetes.api.model.LabelSelectorBuilder;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.strimzi.api.kafka.Crds;
import io.strimzi.api.kafka.model.connect.KafkaConnect;
import io.strimzi.api.kafka.model.connect.KafkaConnectList;
import io.strimzi.operator.common.model.Labels;
import io.strimzi.systemtest.resources.ResourceManager;
import io.strimzi.systemtest.resources.ResourceType;
import io.strimzi.systemtest.utils.kafkaUtils.KafkaConnectUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class KafkaConnectResource implements ResourceType<KafkaConnect> {

    public KafkaConnectResource() { }

    @Override
    public String getKind() {
        return KafkaConnect.RESOURCE_KIND;
    }
    @Override
    public KafkaConnect get(String namespace, String name) {
        return kafkaConnectClient().inNamespace(namespace).withName(name).get();
    }
    @Override
    public void create(KafkaConnect resource) {
        kafkaConnectClient().inNamespace(resource.getMetadata().getNamespace()).resource(resource).create();
    }
    @Override
    public void delete(KafkaConnect resource)    {
        kafkaConnectClient().inNamespace(resource.getMetadata().getNamespace()).withName(
            resource.getMetadata().getName()).withPropagationPolicy(DeletionPropagation.FOREGROUND).delete();
    }

    @Override
    public void update(KafkaConnect resource) {
        kafkaConnectClient().inNamespace(resource.getMetadata().getNamespace()).resource(resource).update();
    }

    @Override
    public boolean waitForReadiness(KafkaConnect resource) {
        return KafkaConnectUtils.waitForConnectReady(resource.getMetadata().getNamespace(), resource.getMetadata().getName());
    }

    public static MixedOperation<KafkaConnect, KafkaConnectList, Resource<KafkaConnect>> kafkaConnectClient() {
        return Crds.kafkaConnectOperation(ResourceManager.kubeClient().getClient());
    }

    public static void replaceKafkaConnectResourceInSpecificNamespace(String resourceName, Consumer<KafkaConnect> editor, String namespaceName) {
        ResourceManager.replaceCrdResource(KafkaConnect.class, KafkaConnectList.class, resourceName, editor, namespaceName);
    }

    public static LabelSelector getLabelSelector(String clusterName, String componentName) {
        Map<String, String> matchLabels = new HashMap<>();
        matchLabels.put(Labels.STRIMZI_CLUSTER_LABEL, clusterName);
        matchLabels.put(Labels.STRIMZI_KIND_LABEL, KafkaConnect.RESOURCE_KIND);
        matchLabels.put(Labels.STRIMZI_NAME_LABEL, componentName);

        return new LabelSelectorBuilder()
                .withMatchLabels(matchLabels)
                .build();
    }
}
