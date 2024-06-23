/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.api.kafka.model.rebalance;

import java.util.List;

public enum KafkaRebalanceState {
    /**
     * The resource has not been observed by the operator before.
     * Transitions to:
     * <dl>
     *     <dt>PendingProposal</dt><dd>If the proposal request was made and it's not ready yet.</dd>
     *     <dt>ProposalReady</dt><dd>If the proposal request was made and it's already ready.</dd>
     *     <dt>NotReady</dt><dd>If the resource is invalid and a request could not be made.</dd>
     * </dl>
     */
    New(List.of()),
    /**
     * A proposal has been requested from Cruise Control, but is not ready yet.
     * Transitions to:
     * <dl>
     *     <dt>PendingProposal</dt><dd>A rebalance proposal is not ready yet.</dd>
     *     <dt>ProposalReady</dt><dd>Once Cruise Control has a ready proposal.</dd>
     *     <dt>NotReady</dt><dd>If Cruise Control returned an error</dd>
     * </dl>
     */
    PendingProposal(List.of(KafkaRebalanceAnnotation.stop, KafkaRebalanceAnnotation.refresh)),
    /**
     * A proposal is ready and waiting for approval.
     * Transitions to:
     * <dl>
     *     <dt>Rebalancing</dt><dd>When the user sets annotation strimzi.io/rebalance=approve.</dd>
     *     <dt>PendingProposal</dt><dd>When the user sets annotation strimzi.io/rebalance=refresh but the proposal is not ready yet.</dd>
     *     <dt>ProposalReady</dt><dd>When the user sets annotation strimzi.io/rebalance=refresh and the proposal is already ready.</dd>
     * </dl>
     */
    ProposalReady(List.of(KafkaRebalanceAnnotation.approve, KafkaRebalanceAnnotation.refresh)),
    /**
     * Cruise Control is doing the rebalance for an approved proposal.
     * Transitions to:
     * <dl>
     *     <dt>Rebalancing</dt><dd>While the actual rebalancing is still ongoing</dd>
     *     <dt>Stopped</dt><dd>If the user sets annotation strimzi.io/rebalance=stop.</dd>
     *     <dt>Ready</dt><dd>Once the rebalancing is complete.</dd>
     *     <dt>ProposalReady</dt><dd>When annotation strimzi.io/rebalance=refresh is applied on rebalance resource and the proposal is updated.</dd>
     * </dl>
     */
    Rebalancing(List.of(KafkaRebalanceAnnotation.stop, KafkaRebalanceAnnotation.refresh)),
    /**
     * The user has stopped the actual rebalancing by setting annotation strimzi.io/rebalance=stop
     * May transition back to:
     * <dl>
     *     <dt>PendingProposal</dt><dd>If the user sets annotation strimzi.io/rebalance=refresh but the proposal is not ready yet.</dd>
     *     <dt>ProposalReady</dt><dd>If the user sets annotation strimzi.io/rebalance=refresh and the proposal is already ready.</dd>
     * </dl>
     */
    Stopped(List.of(KafkaRebalanceAnnotation.refresh)),
    /**
     * There's been some error.
     * Transitions to:
     * <dl>
     *     <dt>New</dt><dd>If the error was caused by the resource itself that was fixed by the user.</dd>
     * </dl>
     */
    NotReady(List.of(KafkaRebalanceAnnotation.refresh)),
    /**
     * The rebalance is complete and there is no transition from this state.
     * The resource is eligible for garbage collection after a configurable delay.
     * There is no transition from this state to a new one.
     */
    Ready(List.of(KafkaRebalanceAnnotation.refresh)),
    /**
     * The user paused reconciliations by setting annotation strimzi.io/pause-reconciliation="true".
     */
    ReconciliationPaused(List.of());

    private final List<KafkaRebalanceAnnotation> validAnnotations;

    KafkaRebalanceState(List<KafkaRebalanceAnnotation> validAnnotations) {
        this.validAnnotations = validAnnotations;
    }

    public boolean isValidateAnnotation(KafkaRebalanceAnnotation annotation) {
        return validAnnotations.contains(annotation);
    }

    public List<KafkaRebalanceAnnotation> getValidAnnotations() {
        return validAnnotations;
    }
}
