/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.api.model.APIGroup;
import io.fabric8.kubernetes.api.model.APIGroupBuilder;
import io.fabric8.kubernetes.api.model.GroupVersionForDiscovery;
import io.fabric8.kubernetes.api.model.GroupVersionForDiscoveryBuilder;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.VersionInfo;
import io.strimzi.platform.KubernetesVersion;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.junit5.Checkpoint;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;


@ExtendWith(VertxExtension.class)
public class PlatformFeaturesAvailabilityTest {
    private final static ObjectMapper OBJECTMAPPER = new ObjectMapper();

    private HttpServer server;

    @Test
    public void testVersionDetectionOpenShift(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        String version = """
                {
                  "major": "%s",
                  "minor": "%S",
                  "gitVersion": "v%s.%s.1",
                  "gitCommit": "c4d752765b3bbac2237bf87cf0b1c2e307844666",
                  "gitTreeState": "clean",
                  "buildDate": "2020-12-18T12:00:47Z",
                  "goVersion": "go1.15.5",
                  "compiler": "gc",
                  "platform": "linux/amd64"
                }"""
                .formatted(KubernetesVersion.MINIMAL_SUPPORTED_MAJOR, KubernetesVersion.MINIMAL_SUPPORTED_MINOR, KubernetesVersion.MINIMAL_SUPPORTED_MAJOR, KubernetesVersion.MINIMAL_SUPPORTED_MINOR);

        startMockApi(vertx, version, Collections.emptyList());

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint a = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.succeeding(pfa -> context.verify(() -> {
            assertThat("Versions are not equal", pfa.getKubernetesVersion(), is(KubernetesVersion.MINIMAL_SUPPORTED_VERSION));
            a.flag();
        })));
    }

    @Test
    public void testVersionDetectionMinikube(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        String version = """
                {
                  "major": "%s",
                  "minor": "%s",
                  "gitVersion": "v%s.%s.1",
                  "gitCommit": "c4d752765b3bbac2237bf87cf0b1c2e307844666",
                  "gitTreeState": "clean",
                  "buildDate": "2020-12-18T12:09:25Z",
                  "goVersion": "go1.15.5",
                  "compiler": "gc",
                  "platform": "linux/amd64"
                }"""
                .formatted(KubernetesVersion.MINIMAL_SUPPORTED_MAJOR, KubernetesVersion.MINIMAL_SUPPORTED_MINOR, KubernetesVersion.MINIMAL_SUPPORTED_MAJOR, KubernetesVersion.MINIMAL_SUPPORTED_MINOR);

        startMockApi(vertx, version, Collections.emptyList());

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint async = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.succeeding(pfa -> context.verify(() -> {
            assertThat("Versions are not equal", pfa.getKubernetesVersion(), is(KubernetesVersion.MINIMAL_SUPPORTED_VERSION));
            async.flag();
        })));
    }

    @Test
    public void testVersionDetectionWrongVersion(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        String version = "Not a proper version JSON";

        startMockApi(vertx, version, Collections.emptyList());

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint async = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.failing(e -> context.verify(() -> {
            assertThat("Versions are not equal", e, instanceOf(KubernetesClientException.class));
            async.flag();
        })));
    }

    @Test
    public void testVersionDetectionFailure(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        startFailingMockApi(vertx);

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint async = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.failing(e -> context.verify(() -> {
            assertThat(e, instanceOf(KubernetesClientException.class));
            assertThat(e.getMessage(), containsString("Forbidden"));
            async.flag();
        })));
    }

    @Test
    public void testApiDetectionOce(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        List<APIGroup> apis = new ArrayList<>();
        apis.add(buildAPIGroup("route.openshift.io", "v1"));
        apis.add(buildAPIGroup("build.openshift.io", "v1"));

        startMockApi(vertx, apis);

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint async = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.succeeding(pfa -> context.verify(() -> {
            assertThat(pfa.hasRoutes(), is(true));
            assertThat(pfa.hasBuilds(), is(true));
            assertThat(pfa.hasImages(), is(false));
            async.flag();
        })));
    }

    @Test
    public void testApiDetectionOpenshift(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        List<APIGroup> apis = new ArrayList<>();
        apis.add(buildAPIGroup("route.openshift.io", "v1"));
        apis.add(buildAPIGroup("build.openshift.io", "v1"));
        apis.add(buildAPIGroup("image.openshift.io", "v1"));

        startMockApi(vertx, apis);

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint async = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.succeeding(pfa -> context.verify(() -> {
            assertThat(pfa.hasRoutes(), is(true));
            assertThat(pfa.hasBuilds(), is(true));
            assertThat(pfa.hasImages(), is(true));
            async.flag();
        })));
    }

    @Test
    public void testApiDetectionWrongAPIVersion(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        List<APIGroup> apis = new ArrayList<>();
        apis.add(buildAPIGroup("route.openshift.io", "v2"));
        apis.add(buildAPIGroup("build.openshift.io", "v1"));
        apis.add(buildAPIGroup("image.openshift.io", "v1"));

        startMockApi(vertx, apis);

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint async = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.succeeding(pfa -> context.verify(() -> {
            assertThat(pfa.hasRoutes(), is(false));
            assertThat(pfa.hasBuilds(), is(true));
            assertThat(pfa.hasImages(), is(true));
            async.flag();
        })));
    }

    @Test
    public void testApiDetectionKubernetes(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        startMockApi(vertx, Collections.emptyList());

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint async = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.succeeding(pfa -> context.verify(() -> {
            assertThat(pfa.hasRoutes(), is(false));
            assertThat(pfa.hasBuilds(), is(false));
            assertThat(pfa.hasImages(), is(false));
            async.flag();
        })));
    }

    @Test
    public void testApiDetectionFailure(Vertx vertx, VertxTestContext context) throws InterruptedException, ExecutionException {
        startFailingMockApi(vertx);

        KubernetesClient client = buildKubernetesClient("127.0.0.1:" + server.actualPort());

        Checkpoint async = context.checkpoint();

        PlatformFeaturesAvailability.create(vertx, client).onComplete(context.failing(e -> context.verify(() -> {
            assertThat(e, instanceOf(KubernetesClientException.class));
            assertThat(e.getMessage(), containsString("Forbidden"));

            async.flag();
        })));
    }

    @Test
    public void versionInfoFromMap(VertxTestContext context) throws ParseException {
        String version = """
                major=1
                minor=16
                gitVersion=v1.16.2
                gitCommit=c97fe5036ef3df2967d086711e6c0c405941e14b
                gitTreeState=clean
                buildDate=2019-10-15T19:09:08Z
                goVersion=go1.12.10
                compiler=gc
                platform=linux/amd64""";

        VersionInfo vi = PlatformFeaturesAvailability.parseVersionInfo(version);

        context.verify(() -> {
            assertThat(vi.getMajor(), is("1"));
            assertThat(vi.getMinor(), is("16"));
        });
        context.completeNow();
    }

    @Test
    public void versionInfoFromMapUnknownFieldIsIgnored(VertxTestContext context) throws ParseException {
        String version = """
                major=1
                minor=16
                gitVersion=v1.16.2
                gitCommit=c97fe5036ef3df2967d086711e6c0c405941e14b
                gitTreeState=clean
                buildDate=2019-10-15T19:09:08Z
                goVersion=go1.12.10
                compiler=gc
                platform=linux/amd64
                unknownKey=someValue""";

        VersionInfo vi = PlatformFeaturesAvailability.parseVersionInfo(version);

        context.verify(() -> {
            assertThat(vi.getMajor(), is("1"));
            assertThat(vi.getMinor(), is("16"));
        });
        context.completeNow();
    }

    KubernetesClient buildKubernetesClient(String masterUrl)    {
        // We have to disable HTTP2 => the mock webserver used here does not support HTTP2 without TLS
        return new KubernetesClientBuilder().withConfig(new ConfigBuilder().withMasterUrl(masterUrl).withHttp2Disable().build()).build();
    }

    void startMockApi(Vertx vertx, String version, List<APIGroup> apis) throws InterruptedException, ExecutionException {
        Set<String> groupsPaths = apis.stream().map(api -> "/apis/" + api.getName()).collect(Collectors.toSet());

        HttpServer httpServer = vertx.createHttpServer().requestHandler(request -> {
            if (HttpMethod.GET.equals(request.method()) && groupsPaths.contains(request.uri())) {
                String groupName = request.uri().substring(request.uri().lastIndexOf("/") + 1);
                APIGroup group = apis.stream().filter(g -> groupName.equals(g.getName())).findFirst().orElse(null);

                try {
                    request.response().setStatusCode(200).end(OBJECTMAPPER.writeValueAsString(group));
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }
            } else if (HttpMethod.GET.equals(request.method()) && "/version".equals(request.uri())) {
                request.response().setStatusCode(200).end(version);
            } else {
                request.response().setStatusCode(404).end();
            }
        });
        server = httpServer.listen(0).toCompletionStage().toCompletableFuture().get();
    }

    void startMockApi(Vertx vertx, List<APIGroup> apis) throws InterruptedException, ExecutionException {
        String version = """
                {
                  "major": "1",
                  "minor": "16",
                  "gitVersion": "v1.9.1+a0ce1bc657",
                  "gitCommit": "a0ce1bc",
                  "gitTreeState": "clean",
                  "buildDate": "2018-06-24T01:54:00Z",
                  "goVersion": "go1.9",
                  "compiler": "gc",
                  "platform": "linux/amd64"
                }""";

        startMockApi(vertx, version, apis);
    }

    private APIGroup buildAPIGroup(String group, String... versions)    {
        APIGroup apiGroup = new APIGroupBuilder()
                .withName(group)
                .build();

        List<GroupVersionForDiscovery> groupVersions = new ArrayList<>();

        for (String version : versions) {
            groupVersions.add(
                    new GroupVersionForDiscoveryBuilder()
                            .withGroupVersion(group + "/" + version)
                            .withVersion(version)
                            .build()
            );
        }

        apiGroup.setVersions(groupVersions);

        return apiGroup;
    }

    void startFailingMockApi(Vertx vertx) throws InterruptedException, ExecutionException {
        HttpServer httpServer = vertx.createHttpServer().requestHandler(request -> {
            // 403 causes a fast failure without retry (for example 500 would cause retry and test will run for a much longer time)
            request.response().setStatusCode(403).setStatusMessage("Mock error").end();
        });

        server = httpServer.listen(0).toCompletionStage().toCompletableFuture().get();
    }


    @AfterEach()
    void teardown() throws ExecutionException, InterruptedException {
        if (server == null) {
            return;
        }

        Promise<Void> serverStopped = Promise.promise();
        server.close(x -> serverStopped.complete());
        serverStopped.future().toCompletionStage().toCompletableFuture().get();
    }
}
