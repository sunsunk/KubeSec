/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.resource.kubernetes;

import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.KubernetesResourceList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.strimzi.operator.common.Reconciliation;
import io.vertx.core.Future;
import io.vertx.core.Vertx;

/**
 * Class used for managing Kubernetes resources which can be watched and have Status. This is used by the assembly
 * operator for access to Custom Resources which have all the status sections.
 *
 * @param <C>   Kubernetes client
 * @param <T>   Kubernetes resource
 * @param <L>   Kubernetes resource list
 * @param <R>   Kubernetes Resource
 */
public abstract class AbstractWatchableStatusedNamespacedResourceOperator<
        C extends KubernetesClient,
        T extends HasMetadata,
        L extends KubernetesResourceList<T>,
        R extends Resource<T>>
        extends AbstractWatchableNamespacedResourceOperator<C, T, L, R> {
    /**
     * Constructor.
     *
     * @param vertx        The vertx instance.
     * @param client       The kubernetes client.
     * @param resourceKind The mind of Kubernetes resource (used for logging).
     */
    public AbstractWatchableStatusedNamespacedResourceOperator(Vertx vertx, C client, String resourceKind) {
        super(vertx, client, resourceKind);
    }

    /**
     * Updates status of the resource
     *
     * @param reconciliation Reconciliation object
     * @param resource  Resource with the status which should be updated in the Kube API server
     * @return          Future with the updated resource
     */
    public abstract Future<T> updateStatusAsync(Reconciliation reconciliation, T resource);
}
