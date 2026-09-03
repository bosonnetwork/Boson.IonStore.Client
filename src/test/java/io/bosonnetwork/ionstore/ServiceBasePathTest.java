/*
 * Copyright (c) 2023 -      bosonnetwork.io
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package io.bosonnetwork.ionstore;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.Signature;

/**
 * The service is not always mounted at the root of its origin: behind a reverse proxy it is
 * commonly published under a path prefix, which the proxy strips before the request reaches the
 * service. That prefix is part of the configured service URL, so every request has to be made
 * under it. These tests pin the derived request path, which the other client tests do not cover -
 * they all point at a URL with no path, where the prefix is empty.
 */
class ServiceBasePathTest {
	private Vertx vertx;
	private HttpServer server;
	private IonStore client;

	/** Every path the stub service was asked for, in order. */
	private final List<String> requestedPaths = new ArrayList<>();

	@BeforeEach
	void setUp() throws Exception {
		vertx = Vertx.vertx();
		server = vertx.createHttpServer().requestHandler(req -> {
			requestedPaths.add(req.path());
			req.response().setStatusCode(404).end();
		});
		server.listen(0).toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
	}

	@AfterEach
	void tearDown() throws Exception {
		if (client != null && !client.isClosed())
			client.close().get(5, TimeUnit.SECONDS);
		if (server != null)
			server.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
		if (vertx != null)
			vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
	}

	/**
	 * Issues one request through a client built on the given URL path suffix, and returns the path
	 * the stub service was actually asked for. The 404 the stub answers with is the expected
	 * outcome here - the request line is what is under test, not what comes back.
	 */
	private String requestedPathFor(String pathSuffix) throws Exception {
		Id id = Id.random();
		client = IonStore.builder()
				.vertx(vertx)
				.userKey(Signature.KeyPair.random())
				.deviceKey(Signature.KeyPair.random())
				.servicePeerId(Id.random())
				.serviceUrl("http://localhost:" + server.actualPort() + pathSuffix)
				.build();

		client.exists(id).toCompletableFuture().get(5, TimeUnit.SECONDS);

		assertEquals(1, requestedPaths.size(), "exactly one request is expected");
		return requestedPaths.get(0).replace(id.toString(), "<id>");
	}

	@Test
	void serviceMountedAtRoot() throws Exception {
		assertEquals("/v1/objects/<id>", requestedPathFor(""));
	}

	@Test
	void serviceMountedAtRootWithTrailingSlash() throws Exception {
		assertEquals("/v1/objects/<id>", requestedPathFor("/"));
	}

	@Test
	void serviceMountedUnderPathPrefix() throws Exception {
		assertEquals("/ion/v1/objects/<id>", requestedPathFor("/ion"));
	}

	@Test
	void serviceMountedUnderPathPrefixWithTrailingSlash() throws Exception {
		assertEquals("/ion/v1/objects/<id>", requestedPathFor("/ion/"));
	}

	@Test
	void redundantTrailingSlashesAreCollapsed() throws Exception {
		// A configured URL is typed by hand, so it can end in more slashes than anyone intended.
		assertEquals("/ion/v1/objects/<id>", requestedPathFor("/ion//"));
	}

	@Test
	void serviceMountedUnderNestedPathPrefix() throws Exception {
		assertEquals("/boson/ion/v1/objects/<id>", requestedPathFor("/boson/ion"));
	}
}
