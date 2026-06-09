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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.Hash;
import io.bosonnetwork.crypto.Signature;
import io.bosonnetwork.ionstore.exceptions.ForbiddenException;
import io.bosonnetwork.ionstore.exceptions.IonStoreException;
import io.bosonnetwork.ionstore.exceptions.ObjectIntegrityException;
import io.bosonnetwork.ionstore.exceptions.ObjectTooLargeException;
import io.bosonnetwork.ionstore.exceptions.PeerResponseException;
import io.bosonnetwork.ionstore.exceptions.QuotaExceededException;
import io.bosonnetwork.ionstore.exceptions.TtlExceededException;

/**
 * Unit tests for the {@link IonStore} client that exercise the download integrity check against a
 * minimal in-process HTTP server (no DHT or full service required), plus {@link IonObject} JSON
 * parsing.
 */
class IonStoreClientTest {
	private static final byte[] PAYLOAD = "Hello, Ion Store!".getBytes(StandardCharsets.UTF_8);

	// Path-segment ids that select the server's behavior.
	private final Id goodId = Id.random();
	private final Id badId = Id.random();
	private final Id missingHeaderId = Id.random();
	private final Id quotaId = Id.random();

	private Vertx vertx;
	private HttpServer server;
	private IonStore client;

	@BeforeEach
	void setUp() throws Exception {
		vertx = Vertx.vertx();

		Id correctContentId = Id.of(Hash.sha256(PAYLOAD));
		Id wrongContentId = Id.random();

		server = vertx.createHttpServer().requestHandler(req -> {
			String path = req.path();
			String id = path.substring(path.lastIndexOf('/') + 1);
			HttpServerResponse resp = req.response();

			if (id.equals(goodId.toString())) {
				resp.putHeader("Content-Type", "application/octet-stream");
				resp.putHeader("Ion-Content-Id", correctContentId.toString());
				resp.putHeader("Ion-Expire-At", "0");
				resp.putHeader("Ion-Filename", "greeting.txt"); // custom Ion-* metadata
				resp.end(Buffer.buffer(PAYLOAD));
			} else if (id.equals(badId.toString())) {
				resp.putHeader("Ion-Content-Id", wrongContentId.toString());
				resp.end(Buffer.buffer(PAYLOAD));
			} else if (id.equals(missingHeaderId.toString())) {
				resp.end(Buffer.buffer(PAYLOAD)); // no Ion-Content-Id
			} else if (id.equals(quotaId.toString())) {
				JsonObject err = new JsonObject()
						.put("type", "QUOTA_EXCEEDED")
						.put("code", 5)
						.put("message", "User quota exceeded: allowed 1048576, used 1048576");
				resp.setStatusCode(429)
						.putHeader("Content-Type", "application/json")
						.end(err.toBuffer());
			} else {
				resp.setStatusCode(404).end();
			}
		});

		int port = server.listen(0).toCompletionStage().toCompletableFuture()
				.get(5, TimeUnit.SECONDS).actualPort();

		client = IonStore.builder()
				.vertx(vertx)
				.userKey(Signature.KeyPair.random())
				.servicePeerId(Id.random())
				.serviceUrl("http://localhost:" + port)
				.build();
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

	@Test
	void downloadVerifiesIntegrityAndReturnsContent() throws Exception {
		BytesIonObject result = client.get(goodId)
				.toCompletableFuture().get(5, TimeUnit.SECONDS);

		assertEquals(PAYLOAD.length, result.getContent().length());
		assertEquals(Buffer.buffer(PAYLOAD), result.getContent());
		assertArrayEquals(PAYLOAD, result.getBytes());
		assertEquals(Id.of(Hash.sha256(PAYLOAD)), result.getContentId());
		assertEquals(goodId, result.getId());
		assertEquals(PAYLOAD.length, result.getSize());
		// custom Ion-* header surfaced as metadata
		assertEquals("greeting.txt", result.getMetadata().get("Ion-Filename"));
	}

	@Test
	void downloadRejectsContentIdMismatch() {
		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(badId).toCompletableFuture().get(5, TimeUnit.SECONDS));
		assertInstanceOf(ObjectIntegrityException.class, e.getCause());
	}

	@Test
	void downloadRejectsMissingContentIdHeader() {
		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(missingHeaderId).toCompletableFuture().get(5, TimeUnit.SECONDS));
		assertInstanceOf(ObjectIntegrityException.class, e.getCause());
	}

	@Test
	void downloadReturnsNullWhenNotFound() throws Exception {
		BytesIonObject result = client.get(Id.random())
				.toCompletableFuture().get(5, TimeUnit.SECONDS);
		assertNull(result);
	}

	@Test
	void serviceErrorResponseIsClassified() {
		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.getIonObject(quotaId).toCompletableFuture().get(5, TimeUnit.SECONDS));
		QuotaExceededException ise = assertInstanceOf(QuotaExceededException.class, e.getCause());
		assertEquals(429, ise.getStatus());
		assertEquals(5, ise.getErrorCode());
		assertEquals("User quota exceeded: allowed 1048576, used 1048576", ise.getMessage());
	}

	@Test
	void fromResponseParsesTypeCodeAndMessage() {
		Buffer body = new JsonObject()
				.put("type", "OBJECT_TOO_LARGE").put("code", 4)
				.put("message", "Object size limit exceeded: allowed 1024").toBuffer();
		IonStoreException e = IonStoreException.fromResponse(413, body);
		assertInstanceOf(ObjectTooLargeException.class, e);
		assertEquals(413, e.getStatus());
		assertEquals(4, e.getErrorCode());
		assertEquals("Object size limit exceeded: allowed 1024", e.getMessage());
	}

	@Test
	void fromResponseDisambiguatesForbiddenFromTtlExceeded() {
		// HTTP 403 is shared by FORBIDDEN and TTL_EXCEEDED; the body's type/code is authoritative.
		Buffer ttl = new JsonObject().put("type", "TTL_EXCEEDED").put("code", 6)
				.put("message", "Object lifetime limit exceeded").toBuffer();
		Buffer forbidden = new JsonObject().put("type", "FORBIDDEN").put("code", 2)
				.put("message", "Forbidden").toBuffer();

		assertInstanceOf(TtlExceededException.class, IonStoreException.fromResponse(403, ttl));
		assertInstanceOf(ForbiddenException.class, IonStoreException.fromResponse(403, forbidden));
	}

	@Test
	void fromResponseMapsAndAppendsFederationPeerDetail() {
		Buffer body = new JsonObject()
				.put("type", "PEER_RESPONSE_ERROR").put("code", 63)
				.put("message", "Peer response error")
				.put("nested", new JsonObject().put("statusCode", 404).put("message", "Object not found"))
				.toBuffer();
		IonStoreException e = IonStoreException.fromResponse(502, body);
		PeerResponseException pre = assertInstanceOf(PeerResponseException.class, e);
		assertEquals("peer responded HTTP 404: Object not found", pre.getNested());
		assertTrue(pre.getMessage().contains("peer responded HTTP 404"));
		assertTrue(pre.getMessage().contains("Object not found"));
	}

	@Test
	void fromResponseResolvesUnknownTypeByCodeAndPreservesRawCode() {
		// A category this client does not know by name, but whose numeric code is recognized.
		Buffer knownCode = new JsonObject().put("type", "FUTURE_CATEGORY").put("code", 5)
				.put("message", "quota").toBuffer();
		assertInstanceOf(QuotaExceededException.class, IonStoreException.fromResponse(429, knownCode));

		// Wholly unknown: surfaces as a plain IonStoreException, but the raw code is still preserved.
		Buffer unknown = new JsonObject().put("type", "FUTURE_CATEGORY").put("code", 9999)
				.put("message", "mystery").toBuffer();
		IonStoreException e = IonStoreException.fromResponse(418, unknown);
		assertEquals(IonStoreException.class, e.getClass());
		assertEquals(9999, e.getErrorCode());
		assertEquals("mystery", e.getMessage());
	}

	@Test
	void fromResponseFallsBackForEmptyAndNonJsonBodies() {
		IonStoreException empty = IonStoreException.fromResponse(500, Buffer.buffer());
		assertEquals(IonStoreException.class, empty.getClass());
		assertEquals(IonStoreException.NO_ERROR_CODE, empty.getErrorCode());
		assertEquals("HTTP 500", empty.getMessage());

		IonStoreException raw = IonStoreException.fromResponse(502, Buffer.buffer("upstream exploded"));
		assertEquals("upstream exploded", raw.getMessage());
	}

	@Test
	void integrityExceptionCarriesNoHttpStatus() {
		ObjectIntegrityException e = new ObjectIntegrityException("hash mismatch");
		assertEquals(11, e.getErrorCode()); // INTEGRITY_ERROR
		assertEquals(IonStoreException.NO_HTTP_STATUS, e.getStatus());
	}

	@Test
	void objectMetadataParsesFromJson() {
		Id id = Id.random();
		Id contentId = Id.random();
		JsonObject json = new JsonObject()
				.put("id", id.toString())
				.put("contentId", contentId.toString())
				.put("name", "file.bin")
				.put("size", 1234L)
				.put("contentType", "application/octet-stream")
				.put("encrypted", true)
				.put("expireAt", 1700000000L)
				.put("metadata", new JsonObject().put("Ion-Tag", "v1"))
				.put("uri", "ions://" + id + "/" + id);

		IonObject meta = IonObject.fromJson(json);
		assertEquals(id, meta.getId());
		assertEquals(contentId, meta.getContentId());
		assertEquals("file.bin", meta.getName());
		assertEquals(1234L, meta.getSize());
		assertEquals("application/octet-stream", meta.getContentType());
		assertTrue(meta.isEncrypted());
		assertEquals(1700000000L, meta.getExpireAt());
		assertEquals(Map.of("Ion-Tag", "v1"), meta.getMetadata());
	}
}