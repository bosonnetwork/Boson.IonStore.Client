package io.bosonnetwork.ionstore;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.WriteStream;
import org.jspecify.annotations.Nullable;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.bosonnetwork.crypto.SecretStream;
import io.bosonnetwork.vertx.AsyncInputStream;

public class DecryptedWriteStreamTest {
	private Vertx vertx;

	@BeforeEach
	void setup() {
		vertx = Vertx.vertx();
	}

	@AfterEach
	void teardown() throws Exception {
		CountDownLatch latch = new CountDownLatch(1);
		vertx.close().onComplete(ar -> latch.countDown());
		latch.await(20, TimeUnit.SECONDS);
	}

	// ---------------------------------------------------------------------
	// Size arithmetic
	// ---------------------------------------------------------------------

	@Test
	void testPlainTextSizeInvertsCipherTextSize() {
		int plainChunk = EncryptedReadStream.DEFAULT_CHUNK_SIZE;
		int encryptedChunk = plainChunk + SecretStream.ABYTES;

		// Boundaries either side of every framing transition, plus the sizes where the ciphertext
		// total lands just past a multiple of the encrypted chunk size while the body has not - the
		// case that breaks if the header is not taken off before the division.
		for (long plain : new long[] {
				0, 1, 2,
				plainChunk - 42, plainChunk - 41, plainChunk - 25, plainChunk - 24, plainChunk - 11,
				plainChunk - 1, plainChunk, plainChunk + 1,
				2L * plainChunk - 1, 2L * plainChunk, 2L * plainChunk + 1,
				7L * plainChunk + 12345 }) {
			long cipher = EncryptedReadStream.getCipherTextSize(plain, plainChunk);
			assertEquals(plain, DecryptedWriteStream.getPlainTextSize(cipher, encryptedChunk),
					"round-trip must be exact for a plaintext of " + plain + " bytes");
		}
	}

	@Test
	void testPlainTextSizeMatchesActualCipherTextLength() throws Exception {
		byte[] key = randomKey();
		int plainChunk = 1024;
		int encryptedChunk = plainChunk + SecretStream.ABYTES;

		for (int plainLen : new int[] { 0, 1, 1023, 1024, 1025, 2048, 3000 }) {
			byte[] cipher = encrypt(randomBytes(plainLen), plainChunk, key, null);
			assertEquals(cipher.length, EncryptedReadStream.getCipherTextSize(plainLen, plainChunk),
					"predicted ciphertext size must match the bytes actually emitted");
			assertEquals(plainLen, DecryptedWriteStream.getPlainTextSize(cipher.length, encryptedChunk),
					"plaintext size must be recoverable from the emitted ciphertext length");
		}
	}

	@Test
	void testPlainTextSizeRejectsUnreachableSizes() {
		// Below the minimum (header + a tag for the always-present final block).
		assertThrows(IllegalArgumentException.class, () -> DecryptedWriteStream.getPlainTextSize(0));
		assertThrows(IllegalArgumentException.class,
				() -> DecryptedWriteStream.getPlainTextSize(SecretStream.HEADER_BYTES));
		assertThrows(IllegalArgumentException.class,
				() -> DecryptedWriteStream.getPlainTextSize(SecretStream.HEADER_BYTES + SecretStream.ABYTES - 1));

		// A body that is an exact multiple of the encrypted chunk size leaves no room for the final
		// block, so no encrypted stream can have that length.
		assertThrows(IllegalArgumentException.class, () -> DecryptedWriteStream.getPlainTextSize(
				SecretStream.HEADER_BYTES + DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE));

		assertThrows(IllegalArgumentException.class,
				() -> DecryptedWriteStream.getPlainTextSize(1024, SecretStream.ABYTES));
	}

	@Test
	void testSizeHelpersAcceptNonPositiveChunkSizeAsDefault() {
		assertEquals(EncryptedReadStream.getCipherTextSize(5000, EncryptedReadStream.DEFAULT_CHUNK_SIZE),
				EncryptedReadStream.getCipherTextSize(5000, 0));
		assertEquals(DecryptedWriteStream.getPlainTextSize(5000, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE),
				DecryptedWriteStream.getPlainTextSize(5000, -1));
	}

	// ---------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------

	private static byte[] randomKey() {
		return io.bosonnetwork.crypto.Random.randomBytes(SecretStream.KEY_BYTES);
	}

	private static byte[] randomBytes(int len) {
		byte[] b = new byte[len];
		new Random().nextBytes(b);
		return b;
	}

	/**
	 * Encrypts {@code plain} through an {@link EncryptedReadStream} and returns the whole encrypted
	 * stream (header followed by ciphertext blocks) as one contiguous byte array.
	 */
	private byte[] encrypt(byte[] plain, int plainChunkSize, byte[] key, byte @Nullable [] aad)
			throws InterruptedException {
		AsyncInputStream source = new AsyncInputStream(vertx, new ByteArrayInputStream(plain), 4096, false);
		EncryptedReadStream enc = new EncryptedReadStream(source, key, plainChunkSize, aad);

		Buffer blob = Buffer.buffer();
		CountDownLatch latch = new CountDownLatch(1);
		enc.handler(blob::appendBuffer);
		enc.endHandler(v -> latch.countDown());

		assertTrue(latch.await(5, TimeUnit.SECONDS), "encryption did not complete within timeout");
		return blob.getBytes();
	}

	/** Convenience overload using the default plain chunk size and no AAD. */
	private byte[] encrypt(byte[] plain, byte[] key) throws InterruptedException {
		return encrypt(plain, EncryptedReadStream.DEFAULT_CHUNK_SIZE, key, null);
	}

	private static void feed(DecryptedWriteStream dec, byte[] blob, int fragmentSize) {
		int offset = 0;
		while (offset < blob.length) {
			int end = Math.min(offset + fragmentSize, blob.length);
			dec.write(Buffer.buffer().appendBytes(blob, offset, end - offset));
			offset = end;
		}
	}

	/** Decrypts an encrypted blob, asserting the stream completes cleanly, and returns the plaintext. */
	private byte[] decrypt(byte[] blob, byte[] key, int encryptedChunkSize, byte @Nullable [] aad, int fragmentSize) {
		BufferCollector collector = new BufferCollector();
		DecryptedWriteStream dec = new DecryptedWriteStream(collector, key, encryptedChunkSize, aad);
		feed(dec, blob, fragmentSize);
		assertTrue(dec.end().succeeded(), "decryption of a well-formed stream should complete");
		assertTrue(collector.ended, "the delegate's end() must be invoked on clean completion");
		return collector.toBuffer().getBytes();
	}

	/**
	 * Feeds an invalid/tampered/truncated blob and asserts decryption fails, returning the reported
	 * cause. Verifies that failure surfaces both via the exception handler and the returned future.
	 */
	private Throwable decryptExpectingFailure(byte[] blob, byte[] key, int encryptedChunkSize,
			byte @Nullable [] aad, int fragmentSize) {
		BufferCollector collector = new BufferCollector();
		DecryptedWriteStream dec = new DecryptedWriteStream(collector, key, encryptedChunkSize, aad);

		AtomicReference<Throwable> handlerError = new AtomicReference<>();
		dec.exceptionHandler(handlerError::set);

		boolean anyWriteFailed = false;
		int offset = 0;
		while (offset < blob.length) {
			int end = Math.min(offset + fragmentSize, blob.length);
			Future<Void> f = dec.write(Buffer.buffer().appendBytes(blob, offset, end - offset));
			anyWriteFailed |= f.failed();
			offset = end;
		}
		Future<Void> endResult = dec.end();

		assertTrue(anyWriteFailed || endResult.failed(),
				"an invalid encrypted stream must fail via a write or end future");
		assertNotNull(handlerError.get(), "the exception handler must be notified of the failure");
		return handlerError.get();
	}

	// ---------------------------------------------------------------------
	// Constants / configuration
	// ---------------------------------------------------------------------

	@Test
	void testDefaultEncryptedChunkSize() {
		assertEquals(32 * 1024, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE);
	}

	@Test
	void testDefaultChunkSizesArePaired() {
		// The decrypt-side full chunk must equal the encrypt-side plain chunk plus the auth tag,
		// otherwise the two sides re-frame the stream differently and authentication fails.
		assertEquals(EncryptedReadStream.DEFAULT_CHUNK_SIZE + SecretStream.ABYTES,
				DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE);
	}

	// ---------------------------------------------------------------------
	// Constructor validation
	// ---------------------------------------------------------------------

	@Test
	void testNullDelegateRejected() {
		WriteStream<Buffer> nullDelegate = null;
		assertThrows(NullPointerException.class,
				() -> new DecryptedWriteStream(nullDelegate, randomKey()));
	}

	@Test
	void testNullKeyRejected() {
		byte[] nullKey = null;
		assertThrows(NullPointerException.class,
				() -> new DecryptedWriteStream(new BufferCollector(), nullKey));
	}

	// ---------------------------------------------------------------------
	// Round-trips (well-formed streams)
	// ---------------------------------------------------------------------

	@Test
	void testRoundTripEncryptThenDecrypt() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(100 * 1024); // > 3 full encrypted chunks

		byte[] blob = encrypt(plain, key);
		byte[] decrypted = decrypt(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);

		assertArrayEquals(plain, decrypted, "decrypted data must match original plaintext");
	}

	@Test
	void testDecryptionWithMisalignedInputChunks() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(50 * 1024);

		byte[] blob = encrypt(plain, key);
		// 1000 is not a power of two and is aligned to neither the header nor the chunk boundary.
		byte[] decrypted = decrypt(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 1000);

		assertArrayEquals(plain, decrypted, "misaligned input fragments must still decrypt correctly");
	}

	@Test
	void testDecryptionWithSingleByteFragments() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(40 * 1024);

		byte[] blob = encrypt(plain, key);
		byte[] decrypted = decrypt(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 1);

		assertArrayEquals(plain, decrypted, "one-byte-at-a-time input must still decrypt correctly");
	}

	@Test
	void testRoundTripEmptyPayload() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(new byte[0], key);

		byte[] decrypted = decrypt(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);

		assertArrayEquals(new byte[0], decrypted, "empty plaintext round-trip must produce empty output");
	}

	@Test
	void testRoundTripExactChunkSizePayload() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(EncryptedReadStream.DEFAULT_CHUNK_SIZE); // exactly one full chunk

		byte[] blob = encrypt(plain, key);
		byte[] decrypted = decrypt(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);

		assertArrayEquals(plain, decrypted, "exact chunk-size plaintext round-trip must match");
	}

	@Test
	void testRoundTripExactMultipleOfChunkSize() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(2 * EncryptedReadStream.DEFAULT_CHUNK_SIZE);

		byte[] blob = encrypt(plain, key);
		byte[] decrypted = decrypt(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);

		assertArrayEquals(plain, decrypted, "exact multiple-of-chunk plaintext round-trip must match");
	}

	@Test
	void testCustomChunkSizeAndAadRoundTrip() throws Exception {
		byte[] key = randomKey();
		byte[] aad = "ion-store/object-42".getBytes();
		int plainChunkSize = 1000;
		byte[] plain = randomBytes(3500);

		byte[] blob = encrypt(plain, plainChunkSize, key, aad);
		byte[] decrypted = decrypt(blob, key, plainChunkSize + SecretStream.ABYTES, aad, 777);

		assertArrayEquals(plain, decrypted, "custom chunk-size and AAD round-trip must match");
	}

	@Test
	void testPipeToRoundTrip() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(75 * 1024);

		AsyncInputStream plainStream = new AsyncInputStream(vertx, new ByteArrayInputStream(plain), 1024, false);
		EncryptedReadStream encryptedStream = new EncryptedReadStream(plainStream, key);

		BufferCollector collector = new BufferCollector();
		DecryptedWriteStream decryptedStream = new DecryptedWriteStream(collector, key);

		CountDownLatch pipeLatch = new CountDownLatch(1);
		AtomicReference<Throwable> pipeError = new AtomicReference<>();
		encryptedStream.pipeTo(decryptedStream).onComplete(ar -> {
			if (ar.failed())
				pipeError.set(ar.cause());
			pipeLatch.countDown();
		});

		assertTrue(pipeLatch.await(5, TimeUnit.SECONDS), "pipe should complete within timeout");
		if (pipeError.get() != null)
			throw new AssertionError("pipe failed", pipeError.get());

		assertArrayEquals(plain, collector.toBuffer().getBytes(), "pipeTo round-trip must produce identical plaintext");
	}

	// ---------------------------------------------------------------------
	// Authentication failures (tampering, wrong key, wrong AAD)
	// ---------------------------------------------------------------------

	@Test
	void testTamperedIntermediateChunkIsRejected() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(100 * 1024), key);

		// Flip a bit inside the first full ciphertext chunk.
		blob[SecretStream.HEADER_BYTES + 100] ^= 0x01;

		decryptExpectingFailure(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);
	}

	@Test
	void testTamperedFinalBlockIsRejected() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(500), key); // single final block

		blob[blob.length - 1] ^= 0x01;

		decryptExpectingFailure(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);
	}

	@Test
	void testReorderedChunksAreRejected() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(100 * 1024), key);

		// Swap the first two full ciphertext chunks; SecretStream binds block order, so this must fail.
		int chunk = DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE;
		int a = SecretStream.HEADER_BYTES;
		int b = SecretStream.HEADER_BYTES + chunk;
		byte[] first = Arrays.copyOfRange(blob, a, a + chunk);
		byte[] second = Arrays.copyOfRange(blob, b, b + chunk);
		System.arraycopy(second, 0, blob, a, chunk);
		System.arraycopy(first, 0, blob, b, chunk);

		decryptExpectingFailure(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);
	}

	@Test
	void testWrongKeyIsRejected() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(40 * 1024), key);

		decryptExpectingFailure(blob, randomKey(), DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);
	}

	@Test
	void testAadMismatchIsRejected() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(2000), EncryptedReadStream.DEFAULT_CHUNK_SIZE, key, "correct-aad".getBytes());

		// Same key, but the AAD supplied at decryption does not match the value used to encrypt.
		decryptExpectingFailure(blob, key, DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, "wrong-aad".getBytes(), 8192);
	}

	// ---------------------------------------------------------------------
	// Truncation detection
	// ---------------------------------------------------------------------

	@Test
	void testTruncatedAtChunkBoundaryIsRejected() throws Exception {
		byte[] key = randomKey();
		// Exact multiple of the chunk size => the final block is a tag-only 17-byte block.
		byte[] blob = encrypt(randomBytes(2 * EncryptedReadStream.DEFAULT_CHUNK_SIZE), key);

		// Drop the tag-only final block: the stream now ends exactly on a full-chunk boundary.
		byte[] truncated = Arrays.copyOf(blob, blob.length - SecretStream.ABYTES);

		Throwable cause = decryptExpectingFailure(truncated, key,
				DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);
		assertTrue(String.valueOf(cause.getMessage()).contains("incomplete or truncated"),
				"boundary truncation must be reported as an incomplete/truncated stream");
	}

	@Test
	void testHeaderOnlyStreamIsRejected() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(10 * 1024), key);

		byte[] headerOnly = Arrays.copyOf(blob, SecretStream.HEADER_BYTES);

		Throwable cause = decryptExpectingFailure(headerOnly, key,
				DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);
		assertTrue(String.valueOf(cause.getMessage()).contains("incomplete or truncated"),
				"a header-only stream must be rejected as incomplete");
	}

	@Test
	void testStreamShorterThanHeaderIsRejected() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(10 * 1024), key);

		byte[] partialHeader = Arrays.copyOf(blob, SecretStream.HEADER_BYTES - 5);

		Throwable cause = decryptExpectingFailure(partialHeader, key,
				DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, null, 8192);
		assertTrue(String.valueOf(cause.getMessage()).contains("incomplete or truncated"),
				"a stream that never completes its header must be rejected");
	}

	// ---------------------------------------------------------------------
	// Lifecycle
	// ---------------------------------------------------------------------

	@Test
	void testWriteAfterEndFails() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(20 * 1024), key);

		BufferCollector collector = new BufferCollector();
		DecryptedWriteStream dec = new DecryptedWriteStream(collector, key);
		feed(dec, blob, 8192);
		assertTrue(dec.end().succeeded(), "clean stream should complete");

		Future<Void> late = dec.write(Buffer.buffer(new byte[8]));
		assertTrue(late.failed(), "writing after end() must fail");
	}

	@Test
	void testWriteAfterTerminationFails() throws Exception {
		byte[] key = randomKey();
		byte[] blob = encrypt(randomBytes(40 * 1024), key);
		blob[SecretStream.HEADER_BYTES + 10] ^= 0x01; // corrupt the first chunk

		BufferCollector collector = new BufferCollector();
		DecryptedWriteStream dec = new DecryptedWriteStream(collector, key);
		AtomicReference<Throwable> err = new AtomicReference<>();
		dec.exceptionHandler(err::set);

		// Writing the whole corrupted blob terminates the stream on the first full chunk.
		dec.write(Buffer.buffer(blob));
		assertNotNull(err.get(), "corruption must terminate the stream via the exception handler");

		Future<Void> late = dec.write(Buffer.buffer(new byte[8]));
		assertTrue(late.failed(), "writing after termination must fail");

		Future<Void> ended = dec.end();
		assertTrue(ended.failed(), "end() after termination must fail");
	}

	@Test
	void testEndOnTerminatedStreamFails() {
		byte[] key = randomKey();
		BufferCollector collector = new BufferCollector();
		DecryptedWriteStream dec = new DecryptedWriteStream(collector, key);

		// Feeding a full-size but garbage chunk fails authentication and terminates the stream.
		dec.write(Buffer.buffer(randomBytes(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE + SecretStream.HEADER_BYTES)));

		assertTrue(dec.end().failed(), "end() on a terminated stream must fail");
	}

	// ---------------------------------------------------------------------
	// Test double
	// ---------------------------------------------------------------------

	/**
	 * A minimal in-memory {@link WriteStream} that collects all written data and records whether
	 * {@link #end()} was invoked.
	 */
	private static class BufferCollector implements WriteStream<Buffer> {
		private final Buffer buffer = Buffer.buffer();
		private boolean ended;

		Buffer toBuffer() {
			return buffer;
		}

		@Override
		public WriteStream<Buffer> exceptionHandler(@Nullable Handler<Throwable> handler) {
			return this;
		}

		@Override
		public Future<Void> write(Buffer data) {
			buffer.appendBuffer(data);
			return Future.succeededFuture();
		}

		@Override
		public Future<Void> end() {
			ended = true;
			return Future.succeededFuture();
		}

		@Override
		public WriteStream<Buffer> setWriteQueueMaxSize(int maxSize) {
			return this;
		}

		@Override
		public boolean writeQueueFull() {
			return false;
		}

		@Override
		public WriteStream<Buffer> drainHandler(@Nullable Handler<Void> handler) {
			return this;
		}
	}
}
