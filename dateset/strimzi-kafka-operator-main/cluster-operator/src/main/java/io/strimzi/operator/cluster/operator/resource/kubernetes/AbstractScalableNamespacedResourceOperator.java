/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.resource.kubernetes;

import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.KubernetesResourceList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.ScalableResource;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.ReconciliationLogger;
import io.vertx.core.Future;
import io.vertx.core.Vertx;

/**
 * An {@link AbstractNamespacedResourceOperator} that can be scaled up and down in addition to the usual operations.
 * @param <C> The type of client used to interact with kubernetes.
 * @param <T> The Kubernetes resource type.
 * @param <L> The list variant of the Kubernetes resource type.
 * @param <R> The resource operations.
 */
public abstract class AbstractScalableNamespacedResourceOperator<C extends KubernetesClient,
            T extends HasMetadata,
            L extends KubernetesResourceList<T>,
            R extends ScalableResource<T>>
        extends AbstractReadyNamespacedResourceOperator<C, T, L, R> {

    private static final ReconciliationLogger LOGGER = ReconciliationLogger.create(AbstractScalableNamespacedResourceOperator.class);

    /**
     * Annotation key for indicating the resource generation
     */
    public static final String ANNO_STRIMZI_IO_GENERATION = Annotations.STRIMZI_DOMAIN + "generation";

    /**
     * Constructor
     * @param vertx The Vertx instance
     * @param client The Kubernetes client
     * @param resourceKind The kind of resource.
     */
    public AbstractScalableNamespacedResourceOperator(Vertx vertx, C client, String resourceKind) {
        super(vertx, client, resourceKind);
    }

    private R resource(String namespace, String name) {
        return operation().inNamespace(namespace).withName(name);
    }

    /**
     * Asynchronously scale up the resource given by {@code namespace} and {@code name} to have the scale given by
     * {@code scaleTo}, returning a future for the outcome. If the resource does not exist, or has a current
     * scale &gt;= the given {@code scaleTo}, then complete successfully.
     *
     * @param reconciliation    The reconciliation
     * @param namespace         The namespace of the resource to scale.
     * @param name              The name of the resource to scale.
     * @param scaleTo           The desired scale.
     * @param timeoutMs         The timeout how long wait for the scaling to happen
     *
     * @return A future whose value is the scale after the operation. If the scale was initially &gt; the given
     *         {@code scaleTo} then this value will be the original scale. The value will be null if the resource didn't
     *         exist (hence no scaling occurred).
     */
    public Future<Integer> scaleUp(Reconciliation reconciliation, String namespace, String name, int scaleTo, long timeoutMs) {
        return vertx.createSharedWorkerExecutor("kubernetes-ops-pool").executeBlocking(
            () -> {
                try {
                    Integer currentScale = currentScale(namespace, name);
                    if (currentScale != null && currentScale < scaleTo) {
                        LOGGER.infoCr(reconciliation, "Scaling up to {} replicas", scaleTo);
                        resource(namespace, name).withTimeoutInMillis(timeoutMs).scale(scaleTo);
                        currentScale = scaleTo;
                    }

                    return currentScale;
                } catch (Exception e) {
                    LOGGER.errorCr(reconciliation, "Caught exception while scaling up", e);
                    throw e;
                }
            }, false);
    }

    protected abstract Integer currentScale(String namespace, String name);

    /**
     * Asynchronously scale down the resource given by {@code namespace} and {@code name} to have the scale given by
     * {@code scaleTo}, returning a future for the outcome. If the resource does not exist, it has a current
     * scale &lt;= the given {@code scaleTo} then complete successfully.
     *
     * @param reconciliation    The reconciliation
     * @param namespace         The namespace of the resource to scale.
     * @param name              The name of the resource to scale.
     * @param scaleTo           The desired scale.
     * @param timeoutMs         The timeout how long wait for the scaling to happen
     *
     * @return A future whose value is the scale after the operation. If the scale was initially &lt; the given
     *         {@code scaleTo} then this value will be the original scale. The value will be null if the resource
     *         didn't exist (hence no scaling occurred).
     */
    public Future<Integer> scaleDown(Reconciliation reconciliation, String namespace, String name, int scaleTo, long timeoutMs) {
        return vertx.createSharedWorkerExecutor("kubernetes-ops-pool").executeBlocking(
            () -> {
                try {
                    Integer nextReplicas = currentScale(namespace, name);
                    if (nextReplicas != null) {
                        while (nextReplicas > scaleTo) {
                            nextReplicas--;
                            LOGGER.infoCr(reconciliation, "Scaling down from {} to {}", nextReplicas + 1, nextReplicas);
                            resource(namespace, name).withTimeoutInMillis(timeoutMs).scale(nextReplicas);
                        }
                    }

                    return nextReplicas;
                } catch (Exception e) {
                    LOGGER.errorCr(reconciliation, "Caught exception while scaling down", e);
                    throw e;
                }
            }, false);
    }
}
