/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.api.kafka.model.mirrormaker2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.strimzi.api.kafka.model.common.Constants;
import io.strimzi.api.kafka.model.connect.KafkaConnectStatus;
import io.strimzi.api.kafka.model.connector.AutoRestartStatus;
import io.strimzi.crdgenerator.annotations.Description;
import io.sundr.builder.annotations.Buildable;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Represents a status of the Kafka MirrorMaker 2 resource
 */
@Buildable(
        editableEnabled = false,
        builderPackage = Constants.FABRIC8_KUBERNETES_API
)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({ "conditions", "observedGeneration", "url", "connectors", "autoRestartStatuses",
    "connectorPlugins", "labelSelector", "replicas" })
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class KafkaMirrorMaker2Status extends KafkaConnectStatus {
    private static final long serialVersionUID = 1L;

    private List<Map<String, Object>> connectors = new ArrayList<>(3);

    private List<AutoRestartStatus> autoRestartStatuses = new ArrayList<>();

    @Description("List of MirrorMaker 2 connector statuses, as reported by the Kafka Connect REST API.")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<Map<String, Object>> getConnectors() {
        return connectors;
    }

    public void setConnectors(List<Map<String, Object>> connectors) {
        this.connectors = connectors;
    }

    @Description("List of MirrorMaker 2 connector auto restart statuses")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<AutoRestartStatus> getAutoRestartStatuses() {
        return autoRestartStatuses;
    }

    public void setAutoRestartStatuses(List<AutoRestartStatus> autoRestartStatuses) {
        this.autoRestartStatuses = autoRestartStatuses;
    }
}