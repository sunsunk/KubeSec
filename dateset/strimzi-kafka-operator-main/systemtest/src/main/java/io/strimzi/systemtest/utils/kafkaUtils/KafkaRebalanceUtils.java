/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.systemtest.utils.kafkaUtils;

import io.strimzi.api.kafka.model.common.Condition;
import io.strimzi.api.kafka.model.rebalance.KafkaRebalance;
import io.strimzi.api.kafka.model.rebalance.KafkaRebalanceAnnotation;
import io.strimzi.api.kafka.model.rebalance.KafkaRebalanceState;
import io.strimzi.api.kafka.model.rebalance.KafkaRebalanceStatus;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.ReconciliationLogger;
import io.strimzi.systemtest.TestConstants;
import io.strimzi.systemtest.resources.ResourceManager;
import io.strimzi.systemtest.resources.ResourceOperation;
import io.strimzi.systemtest.resources.crd.KafkaRebalanceResource;
import io.strimzi.test.TestUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static io.strimzi.test.k8s.KubeClusterResource.kubeClient;

public class KafkaRebalanceUtils {

    private static final ReconciliationLogger LOGGER = ReconciliationLogger.create(KafkaRebalanceUtils.class);

    private KafkaRebalanceUtils() {}

    private static Condition rebalanceStateCondition(Reconciliation reconciliation, String namespaceName, String resourceName) {

        List<Condition> statusConditions = KafkaRebalanceResource.kafkaRebalanceClient().inNamespace(namespaceName)
                .withName(resourceName).get().getStatus().getConditions().stream()
                .filter(condition -> condition.getType() != null)
                .filter(condition -> Arrays.stream(KafkaRebalanceState.values()).anyMatch(stateValue -> stateValue.toString().equals(condition.getType())))
                .collect(Collectors.toList());

        if (statusConditions.size() == 1) {
            return statusConditions.get(0);
        } else if (statusConditions.size() > 1) {
            LOGGER.warnCr(reconciliation, "Multiple KafkaRebalance State Conditions were present in the KafkaRebalance status");
            throw new RuntimeException("Multiple KafkaRebalance State Conditions were present in the KafkaRebalance status");
        } else {
            LOGGER.warnCr(reconciliation, "No KafkaRebalance State Conditions were present in the KafkaRebalance status");
            throw new RuntimeException("No KafkaRebalance State Conditions were present in the KafkaRebalance status");
        }
    }

    public static boolean waitForKafkaRebalanceCustomResourceState(String namespaceName, String resourceName, KafkaRebalanceState state) {
        KafkaRebalance kafkaRebalance = KafkaRebalanceResource.kafkaRebalanceClient().inNamespace(namespaceName).withName(resourceName).get();
        return ResourceManager.waitForResourceStatus(KafkaRebalanceResource.kafkaRebalanceClient(), kafkaRebalance, state, ResourceOperation.getTimeoutForKafkaRebalanceState(state));
    }

    public static boolean waitForKafkaRebalanceCustomResourceState(String resourceName, KafkaRebalanceState state) {
        return waitForKafkaRebalanceCustomResourceState(kubeClient().getNamespace(), resourceName, state);
    }

    public static String annotateKafkaRebalanceResource(Reconciliation reconciliation, String namespaceName, String resourceName, KafkaRebalanceAnnotation annotation) {
        LOGGER.infoCr(reconciliation, "Annotating KafkaRebalance: {} with annotation: {}", resourceName, annotation.toString());
        return ResourceManager.cmdKubeClient().namespace(namespaceName)
            .execInCurrentNamespace("annotate", "kafkarebalance", resourceName, Annotations.ANNO_STRIMZI_IO_REBALANCE + "=" + annotation.toString())
            .out()
            .trim();
    }

    public static String annotateKafkaRebalanceResource(Reconciliation reconciliation, String resourceName, KafkaRebalanceAnnotation annotation) {
        return annotateKafkaRebalanceResource(reconciliation, kubeClient().getNamespace(), resourceName, annotation);
    }

    public static void doRebalancingProcessWithAutoApproval(Reconciliation reconciliation, String namespaceName, String rebalanceName) {
        doRebalancingProcess(reconciliation, namespaceName, rebalanceName, true);
    }

    public static void doRebalancingProcess(Reconciliation reconciliation, String namespaceName, String rebalanceName) {
        doRebalancingProcess(reconciliation, namespaceName, rebalanceName, false);
    }

    public static void doRebalancingProcess(Reconciliation reconciliation, String namespaceName, String rebalanceName, boolean autoApproval) {
        LOGGER.infoCr(reconciliation, String.join("", Collections.nCopies(76, "=")));
        LOGGER.infoCr(reconciliation, KafkaRebalanceResource.kafkaRebalanceClient().inNamespace(namespaceName).withName(rebalanceName).get().getStatus().getConditions().get(0).getType());
        LOGGER.infoCr(reconciliation, String.join("", Collections.nCopies(76, "=")));

        if (!autoApproval) {
            // it can sometimes happen that KafkaRebalance is already in the ProposalReady state -> race condition prevention
            if (!rebalanceStateCondition(reconciliation, namespaceName, rebalanceName).getType().equals(KafkaRebalanceState.ProposalReady.name())) {
                LOGGER.infoCr(reconciliation, "Verifying that KafkaRebalance resource is in {} state", KafkaRebalanceState.ProposalReady);

                waitForKafkaRebalanceCustomResourceState(namespaceName, rebalanceName, KafkaRebalanceState.ProposalReady);
            }

            LOGGER.infoCr(reconciliation, String.join("", Collections.nCopies(76, "=")));
            LOGGER.infoCr(reconciliation, KafkaRebalanceResource.kafkaRebalanceClient().inNamespace(namespaceName).withName(rebalanceName).get().getStatus().getConditions().get(0).getType());
            LOGGER.infoCr(reconciliation, String.join("", Collections.nCopies(76, "=")));

            // using automatic-approval annotation
            final KafkaRebalance kr = KafkaRebalanceResource.kafkaRebalanceClient().inNamespace(namespaceName).withName(rebalanceName).get();
            if (kr.getMetadata().getAnnotations().containsKey(Annotations.ANNO_STRIMZI_IO_REBALANCE_AUTOAPPROVAL) &&
                kr.getMetadata().getAnnotations().get(Annotations.ANNO_STRIMZI_IO_REBALANCE_AUTOAPPROVAL).equals("true")) {
                LOGGER.infoCr(reconciliation, "Triggering the rebalance automatically (because Annotations.ANNO_STRIMZI_IO_REBALANCE_AUTOAPPROVAL is set to true) " +
                    "without an annotation {} of KafkaRebalance resource", "strimzi.io/rebalance=approve");
            } else {
                LOGGER.infoCr(reconciliation, "Triggering the rebalance with annotation {} of KafkaRebalance resource", "strimzi.io/rebalance=approve");

                String response = annotateKafkaRebalanceResource(reconciliation, namespaceName, rebalanceName, KafkaRebalanceAnnotation.approve);

                LOGGER.infoCr(reconciliation, "Response from the annotation process {}", response);
            }
        }

        LOGGER.infoCr(reconciliation, "Verifying that annotation triggers the {} state", KafkaRebalanceState.Rebalancing);

        waitForKafkaRebalanceCustomResourceState(namespaceName, rebalanceName, KafkaRebalanceState.Rebalancing);

        LOGGER.infoCr(reconciliation, "Verifying that KafkaRebalance is in the {} state", KafkaRebalanceState.Ready);

        waitForKafkaRebalanceCustomResourceState(namespaceName, rebalanceName, KafkaRebalanceState.Ready);
    }

    public static void waitForRebalanceStatusStability(Reconciliation reconciliation, String namespaceName, String resourceName) {
        int[] stableCounter = {0};

        KafkaRebalanceStatus oldStatus = KafkaRebalanceResource.kafkaRebalanceClient().inNamespace(namespaceName).withName(resourceName).get().getStatus();

        TestUtils.waitFor("KafkaRebalance status to be stable", TestConstants.GLOBAL_POLL_INTERVAL, TestConstants.GLOBAL_STATUS_TIMEOUT, () -> {
            if (KafkaRebalanceResource.kafkaRebalanceClient().inNamespace(namespaceName).withName(resourceName).get().getStatus().equals(oldStatus)) {
                stableCounter[0]++;
                if (stableCounter[0] == TestConstants.GLOBAL_STABILITY_OFFSET_COUNT) {
                    LOGGER.infoCr(reconciliation, "KafkaRebalance status is stable for: {} poll intervals", stableCounter[0]);
                    return true;
                }
            } else {
                LOGGER.infoCr(reconciliation, "KafkaRebalance status is not stable. Going to set the counter to zero");
                stableCounter[0] = 0;
                return false;
            }
            LOGGER.infoCr(reconciliation, "KafkaRebalance status gonna be stable in {} polls", TestConstants.GLOBAL_STABILITY_OFFSET_COUNT - stableCounter[0]);
            return false;
        });
    }
}
