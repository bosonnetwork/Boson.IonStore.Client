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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.Hash;
import io.bosonnetwork.crypto.SecretStream;
import io.bosonnetwork.crypto.Signature;
import io.bosonnetwork.vertx.ContextualFuture;

/**
 * Wire-contract tests for the fluent {@link IonStore#put()} API: which headers an upload carries and
 * what bytes actually reach the service. Runs against a minimal in-process HTTP server that captures
 * the request and answers like the real service (echoing a content id over the bytes it received, so
 * the client's upload integrity check passes).
 */
class PutRequestUploadTest {
	private Vertx vertx;
	private HttpServer server;
	private IonStore client;

	private final AtomicReference<MultiMap> lastHeaders = new AtomicReference<>();
	private final AtomicReference<Buffer> lastBody = new AtomicReference<>();

	@BeforeEach
	void setUp() throws Exception {
		vertx = Vertx.vertx();

		server = vertx.createHttpServer().requestHandler(req -> {
			lastHeaders.set(req.headers());
			req.body().onSuccess(body -> {
				lastBody.set(body);
				JsonObject obj = new JsonObject()
						.put("id", Id.random().toString())
						.put("contentId", Id.of(Hash.sha256(body.getBytes())).toString())
						.put("size", body.length())
						.put("expireAt", 0L);
				req.response()
						.setStatusCode(201)
						.putHeader("Content-Type", "application/json")
						.end(obj.toBuffer());
			});
		});

		int port = server.listen(0).toCompletionStage().toCompletableFuture()
				.get(5, TimeUnit.SECONDS).actualPort();

		client = IonStore.builder()
				.vertx(vertx)
				.userKey(Signature.KeyPair.random())
				.deviceKey(Signature.KeyPair.random())
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

	private static byte[] randomKey() {
		return io.bosonnetwork.crypto.Random.randomBytes(SecretStream.KEY_BYTES);
	}

	/**
	 * Sends a put from the calling (non-Vert.x) thread and waits for it.
	 * <p>
	 * Calling off a Vert.x context is the point, not an accident: {@code put()} resolves its content
	 * source on a context of its own, so a caller on an ordinary thread gets the same behaviour as
	 * {@code get()}. In-memory sources are backed by {@code ByteArrayReadStream}/
	 * {@code BufferReadStream}, which bind to the current context at construction, and encryption
	 * routes every payload down that path regardless of size - so this would fail if the resolution
	 * ran on the caller's thread.
	 */
	private IonObject send(Supplier<ContextualFuture<IonObject>> action) throws Exception {
		return action.get().get(10, TimeUnit.SECONDS);
	}

	/** Decrypts a captured request body with the raw primitive, independent of the client's own code. */
	private static byte[] decrypt(Buffer cipherText, byte[] key, int encryptedChunkSize) {
		byte[] all = cipherText.getBytes();
		byte[] header = new byte[SecretStream.HEADER_BYTES];
		System.arraycopy(all, 0, header, 0, header.length);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (SecretStream.DecryptionStream dec = SecretStream.decryptionStream(header, key)) {
			int pos = header.length;
			while (pos < all.length) {
				int len = Math.min(encryptedChunkSize, all.length - pos);
				byte[] block = new byte[len];
				System.arraycopy(all, pos, block, 0, len);
				out.writeBytes(dec.pull(block, null));
				pos += len;
			}
			assertTrue(dec.isComplete(), "final block must mark the stream complete");
		}
		return out.toByteArray();
	}

	@Test
	void putResolvesItsContentSourceOffAVertxContext() throws Exception {
		assertNull(Vertx.currentContext(), "this test must drive the client from a plain thread");

		// Both sources that need a Vert.x context to construct their read stream: a payload over the
		// in-memory threshold, and an encrypted payload (which streams at any size).
		byte[] large = io.bosonnetwork.crypto.Random.randomBytes(2 * 1024 * 1024); // over the 1 MiB in-memory threshold
		assertNotNull(send(() -> client.put().content(large).send()),
				"a streamed byte[] put must not require the caller to be on a context");

		byte[] key = randomKey();
		assertNotNull(send(() -> client.put().content(Buffer.buffer("small")).encrypt(key).send()),
				"an encrypted put must not require the caller to be on a context");
	}

	@Test
	void plainPutCarriesNoEncryptionHeaders() throws Exception {
		byte[] payload = "hello ion store".getBytes(StandardCharsets.UTF_8);

		send(() -> client.put().name("greeting.txt").contentType("text/plain").content(payload).send());

		MultiMap headers = lastHeaders.get();
		assertNull(headers.get("Ion-Encrypted"), "an unencrypted put must not be flagged encrypted");
		assertNull(headers.get("Ion-Encryption"), "an unencrypted put carries no encryption descriptor");
		assertEquals("text/plain", headers.get("Content-Type"));
		assertEquals(Integer.toString(payload.length), headers.get("Content-Length"),
				"a small in-memory put must declare its length rather than send chunked");
		assertArrayEquals(payload, lastBody.get().getBytes(), "plaintext must reach the service as-is");
	}

	@Test
	void encryptedPutFlagsAndDescribesTheCipherText() throws Exception {
		byte[] key = randomKey();
		byte[] payload = "attack at dawn".getBytes(StandardCharsets.UTF_8);

		send(() -> client.put().name("secret.txt").content(payload).encrypt(key).send());

		MultiMap headers = lastHeaders.get();
		assertEquals("true", headers.get("Ion-Encrypted"), "an encrypted put must be flagged encrypted");
		assertEquals("secretstream/xchacha20poly1305; chunk=" + IonStore.CHUNK_SIZE,
				headers.get("Ion-Encryption"),
				"the descriptor must name the scheme and the encrypted chunk size");

		Buffer body = lastBody.get();
		assertArrayEquals(payload, decrypt(body, key, IonStore.CHUNK_SIZE),
				"the descriptor's chunk size must be the one the payload was actually framed with");
	}

	@Test
	void encryptedPutDeclaresThePredictedCipherTextLength() throws Exception {
		byte[] key = randomKey();
		byte[] payload = io.bosonnetwork.crypto.Random.randomBytes(3 * IonStore.CHUNK_SIZE_FOR_ENCRYPTION + 777);

		send(() -> client.put().content(payload).encrypt(key).send());

		long predicted = EncryptedReadStream.getCipherTextSize(payload.length, IonStore.CHUNK_SIZE_FOR_ENCRYPTION);
		assertEquals(predicted, lastBody.get().length(),
				"the bytes sent must match the predicted ciphertext size");
		assertEquals(Long.toString(predicted), lastHeaders.get().get("Content-Length"),
				"Content-Length must be declared from the predicted ciphertext size, not the plaintext size");
		assertEquals(payload.length,
				DecryptedWriteStream.getPlainTextSize(lastBody.get().length(), IonStore.CHUNK_SIZE),
				"the stored size must map back to the plaintext size");
	}

	@Test
	void callerMetadataCannotForgeTheEncryptionDescriptor() throws Exception {
		byte[] key = randomKey();

		send(() -> client.put()
				.content("payload".getBytes(StandardCharsets.UTF_8))
				.metadata("Ion-Encryption", "aes-ecb; chunk=1")
				.metadata("Ion-Encrypted", "false")
				.metadata("Tag", "v1")
				.encrypt(key)
				.send());

		MultiMap headers = lastHeaders.get();
		assertEquals("secretstream/xchacha20poly1305; chunk=" + IonStore.CHUNK_SIZE,
				headers.get("Ion-Encryption"), "caller metadata must not override the descriptor");
		assertEquals("true", headers.get("Ion-Encrypted"), "caller metadata must not clear the flag");
		assertEquals("v1", headers.get("Ion-Tag"), "ordinary metadata is still prefixed and sent");
	}

	@Test
	void encryptedFilePutRoundTrips(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
		byte[] key = randomKey();
		byte[] payload = io.bosonnetwork.crypto.Random.randomBytes(2 * IonStore.CHUNK_SIZE_FOR_ENCRYPTION + 13);
		java.nio.file.Path file = dir.resolve("blob.bin");
		java.nio.file.Files.write(file, payload);

		IonObject obj = send(() -> client.put().content(file).encrypt(key).send());

		assertNotNull(obj);
		assertEquals("true", lastHeaders.get().get("Ion-Encrypted"));
		assertArrayEquals(payload, decrypt(lastBody.get(), key, IonStore.CHUNK_SIZE),
				"a file payload must survive the encrypt/upload round trip");
	}
}
