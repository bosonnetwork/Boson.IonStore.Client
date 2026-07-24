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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.Hash;
import io.bosonnetwork.crypto.Random;
import io.bosonnetwork.crypto.SecretStream;
import io.bosonnetwork.crypto.Signature;
import io.bosonnetwork.ionstore.exceptions.DecryptionException;
import io.bosonnetwork.ionstore.exceptions.IonStoreException;
import io.bosonnetwork.ionstore.exceptions.ObjectIntegrityException;
import io.bosonnetwork.vertx.BufferWriteStream;

/**
 * Wire-contract tests for the fluent {@link IonStore#get(Id)} API, run against a minimal in-process
 * service: uploads are stored and then served back the way the real service does, so a put/get pair is
 * a genuine round trip - including the {@code Ion-Encryption} descriptor, which the client writes on
 * one side and parses on the other.
 * <p>
 * Every wait is bounded. That is deliberate: a get that neither succeeds nor fails is a real failure
 * mode here (an early exit that leaves the response body undrained never completes its future), and a
 * timeout is how it shows up.
 */
class GetRequestDownloadTest {
	private static final long TIMEOUT = 5;

	private Vertx vertx;
	private HttpServer server;
	private IonStore client;

	/** Objects the stub "service" is holding, keyed by object id. */
	private final Map<String, Stored> objects = new ConcurrentHashMap<>();
	/** Object ids that make the stub misbehave in a specific way, instead of serving an object. */
	private final Map<String, Fault> faults = new ConcurrentHashMap<>();

	private record Stored(Buffer body, MultiMap headers, JsonObject metadata) {}

	private enum Fault { SERVER_ERROR, NO_CONTENT_ID, WRONG_CONTENT_ID, DROP_CONNECTION }

	@BeforeEach
	void setUp() throws Exception {
		vertx = Vertx.vertx();

		server = vertx.createHttpServer().requestHandler(req -> {
			if (req.method() == HttpMethod.POST) {
				req.body().onSuccess(body -> req.response()
						.setStatusCode(201)
						.putHeader("Content-Type", "application/json")
						.end(store(req.headers(), body).toBuffer()));
				return;
			}

			String path = req.path();
			String id = path.substring(path.lastIndexOf('/') + 1);

			Fault fault = faults.get(id);
			if (fault != null) {
				serveFault(req, fault);
				return;
			}

			Stored stored = objects.get(id);
			if (stored == null) {
				req.response().setStatusCode(404).end();
				return;
			}

			// The service serves metadata and payload from the same URI, told apart by Accept.
			if ("application/json".equals(req.getHeader("Accept"))) {
				req.response().putHeader("Content-Type", "application/json").end(stored.metadata().toBuffer());
				return;
			}

			req.response().headers().addAll(stored.headers());
			req.response().end(stored.body());
		});

		int port = server.listen(0).toCompletionStage().toCompletableFuture()
				.get(TIMEOUT, TimeUnit.SECONDS).actualPort();

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
			client.close().get(TIMEOUT, TimeUnit.SECONDS);
		if (server != null)
			server.close().toCompletionStage().toCompletableFuture().get(TIMEOUT, TimeUnit.SECONDS);
		if (vertx != null)
			vertx.close().toCompletionStage().toCompletableFuture().get(TIMEOUT, TimeUnit.SECONDS);
	}

	/**
	 * Stores an upload and derives the headers the object will be served with, the way the service does:
	 * the content id is computed over the bytes received, and every non-reserved {@code Ion-*} header is
	 * kept as object metadata and echoed back on get - which is how the encryption descriptor survives.
	 */
	private JsonObject store(MultiMap requestHeaders, Buffer body) {
		Id objectId = Id.random();
		Id contentId = Id.of(Hash.sha256(body.getBytes()));

		MultiMap headers = MultiMap.caseInsensitiveMultiMap();
		headers.set("Ion-Content-Id", contentId.toString());
		copyIfPresent(requestHeaders, headers, "Content-Type");
		copyIfPresent(requestHeaders, headers, "Content-Disposition");
		requestHeaders.forEach(e -> {
			if (e.getKey().regionMatches(true, 0, "Ion-", 0, 4)
					&& !e.getKey().equalsIgnoreCase("Ion-Content-Id")
					&& !e.getKey().equalsIgnoreCase("Ion-TTL"))
				headers.set(e.getKey(), e.getValue());
		});

		// The metadata view of the same object: reserved Ion-* names are modelled as their own fields,
		// everything else - the encryption descriptor included - stays in the metadata map.
		JsonObject meta = new JsonObject();
		headers.forEach(e -> {
			if (e.getKey().regionMatches(true, 0, "Ion-", 0, 4)
					&& !e.getKey().equalsIgnoreCase("Ion-Content-Id")
					&& !e.getKey().equalsIgnoreCase("Ion-Encrypted"))
				meta.put(e.getKey(), e.getValue());
		});

		JsonObject object = new JsonObject()
				.put("id", objectId.toString())
				.put("contentId", contentId.toString())
				.put("size", body.length())
				.put("contentType", headers.get("Content-Type"))
				.put("encrypted", "true".equals(headers.get("Ion-Encrypted")))
				.put("expireAt", 0L)
				.put("metadata", meta);

		objects.put(objectId.toString(), new Stored(body, headers, object));

		return object;
	}

	private static void copyIfPresent(MultiMap from, MultiMap to, String name) {
		String value = from.get(name);
		if (value != null)
			to.set(name, value);
	}

	private void serveFault(io.vertx.core.http.HttpServerRequest req, Fault fault) {
		switch (fault) {
			case SERVER_ERROR -> req.response().setStatusCode(500)
					.putHeader("Content-Type", "application/json")
					.end(new JsonObject().put("code", 0).put("message", "boom").toBuffer());
			case NO_CONTENT_ID -> req.response().end(Buffer.buffer("payload with no content id"));
			case WRONG_CONTENT_ID -> req.response()
					.putHeader("Ion-Content-Id", Id.random().toString())
					.end(Buffer.buffer("payload that hashes to something else"));
			case DROP_CONNECTION -> req.connection().close();
		}
	}

	private static byte[] randomKey() {
		return Random.randomBytes(SecretStream.KEY_BYTES);
	}

	/** Uploads a payload and returns the id it can be fetched back under. */
	private Id put(byte[] payload, byte @org.jspecify.annotations.Nullable [] key) throws Exception {
		PutRequest request = client.put().name("blob.bin").contentType("application/octet-stream").content(payload);
		if (key != null)
			request.encrypt(key);
		return request.send().get(TIMEOUT, TimeUnit.SECONDS).getId();
	}

	private Id registerFault(Fault fault) {
		Id id = Id.random();
		faults.put(id.toString(), fault);
		return id;
	}

	// ---------------------------------------------------------------------------------------------
	// Encryption: the put side writes the Ion-Encryption descriptor, the get side has to read it back.
	// ---------------------------------------------------------------------------------------------

	@Test
	void encryptedObjectRoundTripsThroughTheDescriptor() throws Exception {
		byte[] key = randomKey();
		// Spans several chunks plus a partial one, so the framing the descriptor advertises actually
		// matters - a single sub-chunk payload would decrypt even with the wrong chunk size.
		byte[] payload = Random.randomBytes(3 * IonStore.CHUNK_SIZE_FOR_ENCRYPTION + 517);

		Id id = put(payload, key);

		// What the service is holding is the descriptor the client wrote, verbatim.
		assertEquals("secretstream/xchacha20poly1305; chunk=" + IonStore.CHUNK_SIZE,
				objects.get(id.toString()).headers().get("Ion-Encryption"));

		BytesIonObject obj = client.get(id).decrypt(key).toBytes()
				.get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();

		assertArrayEquals(payload, obj.getBytes(), "the plaintext must survive the encrypt/decrypt round trip");
		assertTrue(obj.isEncrypted(), "the metadata still describes the stored, encrypted form");
		assertEquals(EncryptedReadStream.getCipherTextSize(payload.length, IonStore.CHUNK_SIZE_FOR_ENCRYPTION),
				obj.getSize(), "getSize() is the ciphertext length, not the length of the bytes handed back");
	}

	@Test
	void encryptedObjectRoundTripsToAFile(@TempDir Path dir) throws Exception {
		byte[] key = randomKey();
		byte[] payload = Random.randomBytes(2 * IonStore.CHUNK_SIZE_FOR_ENCRYPTION + 11);
		Path file = dir.resolve("out.bin");

		Id id = put(payload, key);
		assertNotNull(client.get(id).decrypt(key).toFile(file).get(TIMEOUT, TimeUnit.SECONDS).orElse(null));

		assertArrayEquals(payload, Files.readAllBytes(file));
	}

	@Test
	void descriptorToleratesWhitespaceAndUnknownParameters() throws Exception {
		byte[] key = randomKey();
		byte[] payload = "tolerant parsing".getBytes(StandardCharsets.UTF_8);

		Id id = put(payload, key);
		// A future writer adds a parameter, pads the separators and cases the name differently - all of
		// which HTTP parameter syntax permits. The chunk size is unchanged, so this must still decrypt.
		objects.get(id.toString()).headers().set("Ion-Encryption",
				" secretstream/xchacha20poly1305 ; v=2 ; CHUNK=" + IonStore.CHUNK_SIZE + " ");

		BytesIonObject obj = client.get(id).decrypt(key).toBytes()
				.get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();
		assertArrayEquals(payload, obj.getBytes());
	}

	@Test
	void malformedDescriptorFailsRatherThanGuessing() throws Exception {
		byte[] key = randomKey();
		Id id = put("whatever".getBytes(StandardCharsets.UTF_8), key);
		objects.get(id.toString()).headers().set("Ion-Encryption", "secretstream/xchacha20poly1305; chunk=abc");

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(id).decrypt(key).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(DecryptionException.class, e.getCause());
	}

	@Test
	void unsupportedSchemeFails() throws Exception {
		byte[] key = randomKey();
		Id id = put("whatever".getBytes(StandardCharsets.UTF_8), key);
		objects.get(id.toString()).headers().set("Ion-Encryption", "aes-ecb; chunk=1024");

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(id).decrypt(key).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(DecryptionException.class, e.getCause());
	}

	@Test
	void encryptedObjectWithoutAKeyFailsInsteadOfYieldingCipherText() throws Exception {
		Id id = put("secret".getBytes(StandardCharsets.UTF_8), randomKey());

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(id).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(DecryptionException.class, e.getCause(),
				"a missing key is a usage error, not an integrity failure");
	}

	@Test
	void wrongKeyFailsAsAClassifiedError() throws Exception {
		Id id = put(Random.randomBytes(4096), randomKey());

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(id).decrypt(randomKey()).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(IonStoreException.class, e.getCause(),
				"a decryption failure must not escape the package's exception hierarchy");
	}

	@Test
	void keyForAnUnencryptedObjectFails() throws Exception {
		Id id = put("in the clear".getBytes(StandardCharsets.UTF_8), null);

		// The caller asked for something confidential and the store has something public. Handing back
		// the plaintext would answer a question that was not asked.
		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(id).decrypt(randomKey()).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(DecryptionException.class, e.getCause());
	}

	@Test
	void rawTakesTheStoredBytesWithoutAKey() throws Exception {
		byte[] key = randomKey();
		byte[] payload = Random.randomBytes(2 * IonStore.CHUNK_SIZE_FOR_ENCRYPTION + 97);
		Id id = put(payload, key);

		// No key, but an explicit request for the stored form: this is how an encrypted object is cached
		// or relayed by someone who cannot read it.
		BytesIonObject stored = client.get(id).raw().toBytes().get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();

		assertEquals(EncryptedReadStream.getCipherTextSize(payload.length, IonStore.CHUNK_SIZE_FOR_ENCRYPTION),
				stored.getBytes().length, "raw() delivers the ciphertext, whole");
		assertEquals(stored.getSize(), stored.getBytes().length, "and getSize() describes exactly that");

		// The ciphertext it handed back is still decryptable, because the framing travelled with the
		// object rather than with the transfer.
		int chunkSize = Integer.parseInt(
				((String) stored.getMetadata().get("Ion-Encryption")).split("chunk=")[1].trim());
		BufferWriteStream plain = vertx.executeBlocking(() -> new BufferWriteStream())
				.toCompletionStage().toCompletableFuture().get(TIMEOUT, TimeUnit.SECONDS);
		DecryptedWriteStream decrypting = new DecryptedWriteStream(plain, key, chunkSize, null);
		decrypting.write(stored.getContent()).toCompletionStage().toCompletableFuture().get(TIMEOUT, TimeUnit.SECONDS);
		decrypting.end().toCompletionStage().toCompletableFuture().get(TIMEOUT, TimeUnit.SECONDS);
		assertArrayEquals(payload, plain.getBuffer().toCompletionStage().toCompletableFuture()
				.get(TIMEOUT, TimeUnit.SECONDS).getBytes());
	}

	@Test
	void rawIsAlsoTheWayToTakeAPlainObjectWithoutClaimingAnything() throws Exception {
		byte[] payload = "public".getBytes(StandardCharsets.UTF_8);
		Id id = put(payload, null);

		assertArrayEquals(payload,
				client.get(id).raw().toBytes().get(TIMEOUT, TimeUnit.SECONDS).orElseThrow().getBytes());
	}

	@Test
	void rawAndDecryptAreMutuallyExclusive() {
		Id id = Id.random();
		assertThrows(IllegalStateException.class, () -> client.get(id).raw().decrypt(randomKey()));
		assertThrows(IllegalStateException.class, () -> client.get(id).decrypt(randomKey()).raw());
	}

	@Test
	void plainTextSizeMapsTheStoredSizeBackToWhatAReaderGets() throws Exception {
		byte[] key = randomKey();
		byte[] payload = Random.randomBytes(5 * IonStore.CHUNK_SIZE_FOR_ENCRYPTION + 3);
		Id id = put(payload, key);

		// Sizing a destination is the point: this is available from the metadata alone, before any
		// payload is transferred.
		IonObject meta = client.getIonObject(id).get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();
		assertTrue(meta.getSize() > payload.length, "the stored size carries the encryption overhead");
		assertEquals(payload.length, meta.getPlainTextSize());

		BytesIonObject obj = client.get(id).decrypt(key).toBytes().get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();
		assertEquals(obj.getPlainTextSize(), obj.getBytes().length,
				"the payload handed back must be the length the object advertises");
	}

	@Test
	void plainTextSizeIsTheStoredSizeWhenNotEncrypted() throws Exception {
		byte[] payload = Random.randomBytes(1234);
		Id id = put(payload, null);

		IonObject obj = client.get(id).toBytes().get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();
		assertEquals(payload.length, obj.getSize());
		assertEquals(obj.getSize(), obj.getPlainTextSize());
	}

	// ---------------------------------------------------------------------------------------------
	// Error paths: each one must complete the future. A hang shows up here as a timeout.
	// ---------------------------------------------------------------------------------------------

	@Test
	void errorStatusFailsPromptly() {
		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(registerFault(Fault.SERVER_ERROR)).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(IonStoreException.class, e.getCause());
	}

	@Test
	void missingContentIdHeaderFailsPromptly() {
		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(registerFault(Fault.NO_CONTENT_ID)).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(ObjectIntegrityException.class, e.getCause());
	}

	@Test
	void contentIdMismatchFailsPromptly() {
		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(registerFault(Fault.WRONG_CONTENT_ID)).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(ObjectIntegrityException.class, e.getCause());
	}

	@Test
	void transportFailureIsWrappedAsAnIonStoreException() {
		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(registerFault(Fault.DROP_CONNECTION)).toBytes().get(TIMEOUT, TimeUnit.SECONDS));
		assertInstanceOf(IonStoreException.class, e.getCause(),
				"a transport error must be classified, not passed through raw");
	}

	// ---------------------------------------------------------------------------------------------
	// Destinations
	// ---------------------------------------------------------------------------------------------

	@Test
	void everyDestinationReceivesThePayload(@TempDir Path dir) throws Exception {
		byte[] payload = Random.randomBytes(64 * 1024);
		Id id = put(payload, null);

		BytesIonObject bytes = client.get(id).toBytes().get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();
		assertArrayEquals(payload, bytes.getBytes());
		assertEquals("blob.bin", bytes.getName());
		assertEquals("application/octet-stream", bytes.getContentType());

		Path file = dir.resolve("out.bin");
		assertNotNull(client.get(id).toFile(file).get(TIMEOUT, TimeUnit.SECONDS).orElse(null));
		assertArrayEquals(payload, Files.readAllBytes(file));

		ByteArrayOutputStream os = new ByteArrayOutputStream();
		assertNotNull(client.get(id).toOutputStream(os).get(TIMEOUT, TimeUnit.SECONDS).orElse(null));
		assertArrayEquals(payload, os.toByteArray());

		// A WriteStream destination has to be built on a context; the caller here is not on one, which is
		// why this is created inside runOnContext while everything else is called from the test thread.
		Buffer collected = vertx.executeBlocking(() -> null)
				.compose(v -> {
					BufferWriteStream ws = new BufferWriteStream();
					return io.vertx.core.Future.fromCompletionStage(client.get(id).toWriteStream(ws))
							.compose(meta -> ws.getBuffer());
				})
				.toCompletionStage().toCompletableFuture().get(TIMEOUT, TimeUnit.SECONDS);
		assertArrayEquals(payload, collected.getBytes());
	}

	@Test
	void bufferDestinationAppendsToTheGivenAccumulator() throws Exception {
		byte[] first = "first".getBytes(StandardCharsets.UTF_8);
		byte[] second = "second".getBytes(StandardCharsets.UTF_8);

		// Assembling two objects into one buffer is what this destination is for, and it is why it
		// returns metadata only: neither object can claim the accumulator as "its" content.
		Buffer accumulator = Buffer.buffer();
		IonObject one = client.get(put(first, null)).toBuffer(accumulator).get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();
		IonObject two = client.get(put(second, null)).toBuffer(accumulator).get(TIMEOUT, TimeUnit.SECONDS).orElseThrow();

		assertEquals(first.length, one.getSize());
		assertEquals(second.length, two.getSize());
		assertArrayEquals(Buffer.buffer().appendBytes(first).appendBytes(second).getBytes(), accumulator.getBytes());
	}

	@Test
	void missingObjectYieldsAnEmptyResultAndLeavesNoFileBehind(@TempDir Path dir) throws Exception {
		Path file = dir.resolve("absent.bin");

		Optional<BytesIonObject> bytes = client.get(Id.random()).toBytes().get(TIMEOUT, TimeUnit.SECONDS);
		assertTrue(bytes.isEmpty());

		Optional<IonObject> toFile = client.get(Id.random()).toFile(file).get(TIMEOUT, TimeUnit.SECONDS);
		assertTrue(toFile.isEmpty());
		assertFalse(Files.exists(file), "a file created for an object that turned out to be missing is rolled back");
	}

	@Test
	void anOwnedOutputStreamIsClosedOnEveryOutcome() throws Exception {
		// A stream this client was told to close has to be closed even when no payload arrives - the
		// pipe never runs in that case, so nothing else would ever end it.
		ClosableOutputStream missing = new ClosableOutputStream();
		assertTrue(client.get(Id.random()).toOutputStream(missing, true)
				.get(TIMEOUT, TimeUnit.SECONDS).isEmpty());
		assertTrue(missing.closed, "a miss must still close a stream this client owns");

		ClosableOutputStream failed = new ClosableOutputStream();
		assertThrows(ExecutionException.class, () -> client.get(registerFault(Fault.NO_CONTENT_ID))
				.toOutputStream(failed, true).get(TIMEOUT, TimeUnit.SECONDS));
		assertTrue(failed.closed, "a failure raised from the response headers must still close it");

		ClosableOutputStream transferred = new ClosableOutputStream();
		Id id = put("payload".getBytes(StandardCharsets.UTF_8), null);
		assertNotNull(client.get(id).toOutputStream(transferred, true)
				.get(TIMEOUT, TimeUnit.SECONDS).orElse(null));
		assertTrue(transferred.closed);
		assertEquals(1, transferred.closeCount, "a completed transfer must not close it twice");

		ClosableOutputStream borrowed = new ClosableOutputStream();
		assertNotNull(client.get(id).toOutputStream(borrowed).get(TIMEOUT, TimeUnit.SECONDS).orElse(null));
		assertFalse(borrowed.closed, "a stream the caller retains ownership of is never closed");
	}

	private static final class ClosableOutputStream extends ByteArrayOutputStream {
		volatile boolean closed;
		volatile int closeCount;

		@Override
		public void close() {
			closed = true;
			closeCount++;
		}
	}

	@Test
	void failedTransferLeavesNoFileBehind(@TempDir Path dir) throws Exception {
		Path file = dir.resolve("corrupt.bin");

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> client.get(registerFault(Fault.WRONG_CONTENT_ID)).toFile(file).get(TIMEOUT, TimeUnit.SECONDS));

		// The rollback runs after a transfer that itself succeeded, so it has to survive a destination
		// the pipe has already closed - without either swallowing the error or skipping the delete.
		assertInstanceOf(ObjectIntegrityException.class, e.getCause(),
				"the rollback must not replace the error that caused it");
		assertFalse(Files.exists(file), "a file holding an unverified payload is rolled back");
	}

	@Test
	void requestIsReusableAcrossDestinations() throws Exception {
		byte[] payload = "reused".getBytes(StandardCharsets.UTF_8);
		Id id = put(payload, null);

		GetRequest request = client.get(id);
		assertArrayEquals(payload, request.toBytes().get(TIMEOUT, TimeUnit.SECONDS).orElseThrow().getBytes());

		ByteArrayOutputStream os = new ByteArrayOutputStream();
		assertNotNull(request.toOutputStream(os).get(TIMEOUT, TimeUnit.SECONDS).orElse(null));
		assertArrayEquals(payload, os.toByteArray());
	}

	@Test
	void getIsUsableFromAPlainThread() throws Exception {
		assertNull(Vertx.currentContext(), "this test must drive the client from a plain thread");

		byte[] payload = Random.randomBytes(1024);
		Id id = put(payload, null);

		// The in-memory destination binds to a Vert.x context at construction, so this only works because
		// the client puts itself on one first - both on the fluent path and on the deprecated one.
		assertArrayEquals(payload, client.get(id).toBytes().get(TIMEOUT, TimeUnit.SECONDS).orElseThrow().getBytes());
	}
}