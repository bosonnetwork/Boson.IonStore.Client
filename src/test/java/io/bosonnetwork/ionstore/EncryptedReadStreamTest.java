package io.bosonnetwork.ionstore;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;
import org.jspecify.annotations.Nullable;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.bosonnetwork.crypto.SecretStream;
import io.bosonnetwork.vertx.AsyncInputStream;

public class EncryptedReadStreamTest {
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
	 * Encrypts {@code plain} by driving it through an {@link EncryptedReadStream} backed by an
	 * {@link AsyncInputStream}, and returns the ordered list of emitted buffers (header first,
	 * followed by ciphertext blocks). Fails the test if encryption does not complete in time or
	 * raises an exception.
	 */
	private List<Buffer> encrypt(byte[] plain, int sourceChunkSize, byte[] key, int chunkSize,
			byte @Nullable [] aad) throws InterruptedException {
		AsyncInputStream source = new AsyncInputStream(vertx, new ByteArrayInputStream(plain), sourceChunkSize, false);
		EncryptedReadStream enc = new EncryptedReadStream(source, key, chunkSize, aad);

		List<Buffer> out = new ArrayList<>();
		AtomicReference<Throwable> err = new AtomicReference<>();
		CountDownLatch latch = new CountDownLatch(1);

		enc.exceptionHandler(t -> {
			err.set(t);
			latch.countDown();
		});
		enc.handler(out::add);
		enc.endHandler(v -> latch.countDown());

		assertTrue(latch.await(5, TimeUnit.SECONDS), "encryption did not complete within timeout");
		assertNull(err.get(), "encryption raised an unexpected exception: " + err.get());
		return out;
	}

	/** Convenience overload using the default plain chunk size and no AAD. */
	private List<Buffer> encrypt(byte[] plain, int sourceChunkSize, byte[] key) throws InterruptedException {
		return encrypt(plain, sourceChunkSize, key, EncryptedReadStream.DEFAULT_CHUNK_SIZE, null);
	}

	/**
	 * Independently decrypts an encrypted buffer list (as produced by {@link #encrypt}) using a raw
	 * {@link SecretStream.DecryptionStream}, asserting the stream reports completion once the final
	 * block is consumed. This deliberately avoids {@link DecryptedWriteStream} so the read side is
	 * validated against the underlying primitive, not its sibling wrapper.
	 */
	private byte[] decrypt(List<Buffer> encrypted, byte[] key, byte @Nullable [] aad) {
		assertFalse(encrypted.isEmpty(), "encrypted output must at least contain a header");
		byte[] header = encrypted.get(0).getBytes();
		assertEquals(SecretStream.HEADER_BYTES, header.length, "first buffer must be the stream header");

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (SecretStream.DecryptionStream dec = SecretStream.decryptionStream(header, key)) {
			for (int i = 1; i < encrypted.size(); i++)
				out.writeBytes(dec.pull(encrypted.get(i).getBytes(), aad));
			assertTrue(dec.isComplete(), "decryption stream must be marked complete by the final block");
		}
		return out.toByteArray();
	}

	private static int totalLength(List<Buffer> buffers) {
		int total = 0;
		for (Buffer b : buffers)
			total += b.length();
		return total;
	}

	// ---------------------------------------------------------------------
	// Constant / configuration
	// ---------------------------------------------------------------------

	@Test
	void testDefaultChunkSize() {
		assertEquals(32 * 1024 - SecretStream.ABYTES, EncryptedReadStream.DEFAULT_CHUNK_SIZE);
	}

	@Test
	void testDefaultChunkPlusOverheadIsFullEncryptedChunk() {
		// A full plain chunk encrypts to exactly the decrypt-side's full encrypted chunk size.
		assertEquals(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE,
				EncryptedReadStream.DEFAULT_CHUNK_SIZE + SecretStream.ABYTES);
	}

	// ---------------------------------------------------------------------
	// Constructor validation
	// ---------------------------------------------------------------------

	@Test
	void testNullDelegateRejected() {
		ReadStream<Buffer> nullDelegate = null;
		assertThrows(NullPointerException.class,
				() -> new EncryptedReadStream(nullDelegate, randomKey()));
	}

	@Test
	void testInvalidKeyLengthRejected() {
		AsyncInputStream source = new AsyncInputStream(vertx, new ByteArrayInputStream(new byte[0]), 1024, false);
		assertThrows(IllegalArgumentException.class,
				() -> new EncryptedReadStream(source, new byte[16]));
	}

	// ---------------------------------------------------------------------
	// Framing invariants and round-trips
	// ---------------------------------------------------------------------

	@Test
	void testHeaderEmittedFirstWithExactSize() throws Exception {
		byte[] key = randomKey();
		List<Buffer> encrypted = encrypt(randomBytes(200), 1024, key);

		assertEquals(SecretStream.HEADER_BYTES, encrypted.get(0).length(),
				"first emitted buffer must be the SecretStream header");
	}

	@Test
	void testEmptyPayloadEmitsHeaderAndFinalBlockOnly() throws Exception {
		byte[] key = randomKey();
		List<Buffer> encrypted = encrypt(new byte[0], 1024, key);

		// Even with no plaintext, the stream still yields a header plus a (nonzero) final block.
		assertEquals(2, encrypted.size(), "empty payload must yield exactly header + final block");
		assertEquals(SecretStream.HEADER_BYTES, encrypted.get(0).length());
		assertEquals(SecretStream.ABYTES, encrypted.get(1).length(),
				"final block for empty payload is just the auth tag overhead");

		assertArrayEquals(new byte[0], decrypt(encrypted, key, null),
				"empty payload must round-trip to empty plaintext");
	}

	@Test
	void testSubChunkPayloadIsSingleFinalBlock() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(100); // well below one plain chunk

		List<Buffer> encrypted = encrypt(plain, 1024, key);

		assertEquals(2, encrypted.size(), "sub-chunk payload must yield header + one final block");
		assertEquals(plain.length + SecretStream.ABYTES, encrypted.get(1).length(),
				"final block holds the plaintext plus auth tag, with no padding");
		assertArrayEquals(plain, decrypt(encrypted, key, null));
	}

	@Test
	void testExactChunkSizePayload() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(EncryptedReadStream.DEFAULT_CHUNK_SIZE);

		List<Buffer> encrypted = encrypt(plain, 8192, key);

		// One full non-final chunk, then a final block carrying only the tag (no leftover plaintext).
		assertEquals(3, encrypted.size());
		assertEquals(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, encrypted.get(1).length(),
				"the one full chunk must be exactly 32 KiB");
		assertEquals(SecretStream.ABYTES, encrypted.get(2).length(),
				"final block is the tag only when plaintext divides evenly");
		assertArrayEquals(plain, decrypt(encrypted, key, null));
	}

	@Test
	void testExactMultipleOfChunkSize() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(2 * EncryptedReadStream.DEFAULT_CHUNK_SIZE);

		List<Buffer> encrypted = encrypt(plain, 8192, key);

		assertEquals(4, encrypted.size(), "header + two full chunks + tag-only final block");
		assertEquals(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, encrypted.get(1).length());
		assertEquals(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, encrypted.get(2).length());
		assertEquals(SecretStream.ABYTES, encrypted.get(3).length());
		assertArrayEquals(plain, decrypt(encrypted, key, null));
	}

	@Test
	void testMultiChunkFixedFramingAndRoundTrip() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(100 * 1024); // spans more than three full plain chunks

		List<Buffer> encrypted = encrypt(plain, 1024, key);

		// First buffer is the header.
		assertEquals(SecretStream.HEADER_BYTES, encrypted.get(0).length());

		// Every intermediate ciphertext block (all but header and final) must be a full 32 KiB.
		for (int i = 1; i < encrypted.size() - 1; i++)
			assertEquals(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, encrypted.get(i).length(),
					"intermediate encrypted chunk " + i + " must be 32 KiB");

		// The final block carries only the unpadded remainder plus the auth tag.
		int remainder = plain.length % EncryptedReadStream.DEFAULT_CHUNK_SIZE;
		Buffer finalBlock = encrypted.get(encrypted.size() - 1);
		assertEquals(remainder + SecretStream.ABYTES, finalBlock.length(),
				"final block must hold only the remaining plaintext plus the auth tag");

		// Total ciphertext = header + one tag per chunk over the whole plaintext.
		int chunkCount = encrypted.size() - 1;
		assertEquals(SecretStream.HEADER_BYTES + plain.length + chunkCount * SecretStream.ABYTES,
				totalLength(encrypted));

		assertArrayEquals(plain, decrypt(encrypted, key, null));
	}

	@Test
	void testTinySourceReadsAreReassembled() throws Exception {
		byte[] key = randomKey();
		byte[] plain = randomBytes(40 * 1024);

		// Source delivers one byte at a time; framing must still align to full plain chunks.
		List<Buffer> encrypted = encrypt(plain, 1, key);

		assertEquals(SecretStream.HEADER_BYTES, encrypted.get(0).length());
		assertEquals(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, encrypted.get(1).length(),
				"one full plain chunk must accumulate even from 1-byte source reads");
		assertArrayEquals(plain, decrypt(encrypted, key, null));
	}

	@Test
	void testCustomChunkSizeFramingAndRoundTrip() throws Exception {
		byte[] key = randomKey();
		int chunkSize = 1000;
		byte[] plain = randomBytes(3500); // 3 full chunks + 500-byte remainder

		List<Buffer> encrypted = encrypt(plain, 256, key, chunkSize, null);

		assertEquals(5, encrypted.size(), "header + 3 full chunks + final remainder block");
		for (int i = 1; i <= 3; i++)
			assertEquals(chunkSize + SecretStream.ABYTES, encrypted.get(i).length(),
					"intermediate chunk " + i + " must be chunkSize + tag");
		assertEquals(500 + SecretStream.ABYTES, encrypted.get(4).length());
		assertArrayEquals(plain, decrypt(encrypted, key, null));
	}

	// ---------------------------------------------------------------------
	// Additional authenticated data (AAD)
	// ---------------------------------------------------------------------

	@Test
	void testAadRoundTrip() throws Exception {
		byte[] key = randomKey();
		byte[] aad = "ion-store/object-42".getBytes();
		byte[] plain = randomBytes(70 * 1024);

		List<Buffer> encrypted = encrypt(plain, 4096, key, EncryptedReadStream.DEFAULT_CHUNK_SIZE, aad);

		assertArrayEquals(plain, decrypt(encrypted, key, aad),
				"payload encrypted with AAD must decrypt when the same AAD is supplied");
	}

	@Test
	void testAadMismatchFailsDecryption() throws Exception {
		byte[] key = randomKey();
		byte[] aad = "correct-aad".getBytes();
		byte[] plain = randomBytes(500);

		List<Buffer> encrypted = encrypt(plain, 1024, key, EncryptedReadStream.DEFAULT_CHUNK_SIZE, aad);

		byte[] header = encrypted.get(0).getBytes();
		try (SecretStream.DecryptionStream dec = SecretStream.decryptionStream(header, key)) {
			byte[] block = encrypted.get(1).getBytes();
			// Authentication must fail when the AAD does not match the value used for encryption.
			assertThrows(Exception.class, () -> dec.pull(block, "wrong-aad".getBytes()));
		}
	}

	// ---------------------------------------------------------------------
	// Stream lifecycle and back-pressure
	// ---------------------------------------------------------------------

	@Test
	void testEndHandlerFiredExactlyOnce() throws Exception {
		byte[] key = randomKey();
		AsyncInputStream source = new AsyncInputStream(vertx, new ByteArrayInputStream(randomBytes(50 * 1024)), 4096, false);
		EncryptedReadStream enc = new EncryptedReadStream(source, key);

		AtomicInteger endCount = new AtomicInteger();
		CountDownLatch latch = new CountDownLatch(1);
		enc.handler(b -> { });
		enc.endHandler(v -> {
			endCount.incrementAndGet();
			latch.countDown();
		});

		assertTrue(latch.await(5, TimeUnit.SECONDS), "stream should end");
		// Give the event loop a brief window to (incorrectly) fire a second end event.
		Thread.sleep(100);
		assertEquals(1, endCount.get(), "endHandler must be invoked exactly once");
	}

	@Test
	void testPauseWithholdsDataUntilResume() {
		byte[] key = randomKey();
		FakeReadStream source = new FakeReadStream();
		EncryptedReadStream enc = new EncryptedReadStream(source, key);

		List<Buffer> out = new ArrayList<>();
		enc.handler(out::add);
		enc.endHandler(v -> { });

		// Pausing the encrypted stream must pause the delegate: buffered source data stays undelivered.
		enc.pause();
		source.supply(Buffer.buffer(randomBytes(100)));
		assertTrue(out.isEmpty(), "no output expected while paused");

		// Resuming lets the buffered chunk flow; the header is emitted with the first data.
		enc.resume();
		assertFalse(out.isEmpty(), "resuming must flush the buffered data");
		assertEquals(SecretStream.HEADER_BYTES, out.get(0).length(),
				"first delivered buffer after resume must be the header");
	}

	@Test
	void testFetchDeliversBoundedDemand() {
		byte[] key = randomKey();
		FakeReadStream source = new FakeReadStream();
		EncryptedReadStream enc = new EncryptedReadStream(source, key);

		List<Buffer> out = new ArrayList<>();
		enc.handler(out::add);
		enc.endHandler(v -> { });

		enc.pause();
		// Two full plain chunks are available at the source.
		source.supply(Buffer.buffer(randomBytes(EncryptedReadStream.DEFAULT_CHUNK_SIZE)));
		source.supply(Buffer.buffer(randomBytes(EncryptedReadStream.DEFAULT_CHUNK_SIZE)));
		assertTrue(out.isEmpty());

		// Demand for a single source buffer: header + first full ciphertext chunk.
		enc.fetch(1);
		assertEquals(2, out.size(), "one source buffer yields header + one chunk");
		assertEquals(SecretStream.HEADER_BYTES, out.get(0).length());
		assertEquals(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, out.get(1).length());

		// Releasing the rest delivers the second chunk (header already sent).
		enc.fetch(1);
		assertEquals(3, out.size());
		assertEquals(DecryptedWriteStream.DEFAULT_ENCRYPTED_CHUNK_SIZE, out.get(2).length());
	}

	@Test
	void testHandlerNullDetachesDelegate() {
		byte[] key = randomKey();
		FakeReadStream source = new FakeReadStream();
		EncryptedReadStream enc = new EncryptedReadStream(source, key);

		List<Buffer> out = new ArrayList<>();
		enc.handler(out::add);
		enc.handler(null); // detach

		assertNull(source.dataHandler, "clearing the handler must detach the delegate handler");
		source.supply(Buffer.buffer(randomBytes(100)));
		assertTrue(out.isEmpty(), "no output expected after the handler is detached");
	}

	@Test
	void testDelegateExceptionIsPropagated() {
		byte[] key = randomKey();
		FakeReadStream source = new FakeReadStream();
		EncryptedReadStream enc = new EncryptedReadStream(source, key);

		AtomicReference<Throwable> received = new AtomicReference<>();
		enc.exceptionHandler(received::set);
		enc.handler(b -> { });

		RuntimeException boom = new RuntimeException("source failure");
		source.fail(boom);

		assertSame(boom, received.get(), "delegate exceptions must reach the exception handler");
	}

	@Test
	void testDownstreamHandlerErrorTerminatesStream() {
		byte[] key = randomKey();
		FakeReadStream source = new FakeReadStream();
		EncryptedReadStream enc = new EncryptedReadStream(source, key);

		RuntimeException boom = new RuntimeException("downstream failure");
		AtomicReference<Throwable> received = new AtomicReference<>();
		AtomicInteger delivered = new AtomicInteger();

		enc.exceptionHandler(received::set);
		enc.handler(b -> {
			delivered.incrementAndGet();
			throw boom; // fail while handling the very first (header) buffer
		});
		enc.endHandler(v -> { });

		source.supply(Buffer.buffer(randomBytes(100)));

		assertSame(boom, received.get(), "an error thrown downstream must surface via the exception handler");
		assertEquals(1, delivered.get(), "delivery stops at the failing buffer");

		// After termination the delegate is paused; further source data must not be delivered.
		int before = delivered.get();
		source.supply(Buffer.buffer(randomBytes(100)));
		assertEquals(before, delivered.get(), "no further delivery after termination");
	}

	// ---------------------------------------------------------------------
	// Test double
	// ---------------------------------------------------------------------

	/**
	 * A minimal synchronous in-memory {@link ReadStream} that honors demand, letting tests exercise
	 * pause / resume / fetch back-pressure and exception propagation deterministically (no event loop).
	 */
	private static final class FakeReadStream implements ReadStream<Buffer> {
		private @Nullable Handler<Buffer> dataHandler;
		private @Nullable Handler<Void> endHandler;
		private @Nullable Handler<Throwable> exceptionHandler;

		private final Deque<Buffer> queue = new ArrayDeque<>();
		private long demand = Long.MAX_VALUE; // flowing by default

		/** Offer a buffer from the "source"; delivered immediately if there is demand, else queued. */
		void supply(Buffer buffer) {
			queue.add(buffer);
			flush();
		}

		/** Raise an error on the stream. */
		void fail(Throwable t) {
			if (exceptionHandler != null)
				exceptionHandler.handle(t);
		}

		private void flush() {
			while (dataHandler != null && demand > 0L && !queue.isEmpty()) {
				if (demand != Long.MAX_VALUE)
					demand--;
				dataHandler.handle(queue.poll());
			}
		}

		@Override
		public FakeReadStream handler(@Nullable Handler<Buffer> handler) {
			this.dataHandler = handler;
			if (handler != null)
				flush();
			return this;
		}

		@Override
		public FakeReadStream exceptionHandler(@Nullable Handler<Throwable> handler) {
			this.exceptionHandler = handler;
			return this;
		}

		@Override
		public FakeReadStream endHandler(@Nullable Handler<Void> handler) {
			this.endHandler = handler;
			if (handler != null)
				flush();
			return this;
		}

		@Override
		public FakeReadStream pause() {
			demand = 0L;
			return this;
		}

		@Override
		public FakeReadStream resume() {
			return fetch(Long.MAX_VALUE);
		}

		@Override
		public FakeReadStream fetch(long amount) {
			if (amount < 0)
				throw new IllegalArgumentException("amount must be >= 0");
			demand += amount;
			if (demand < 0L)
				demand = Long.MAX_VALUE;
			flush();
			return this;
		}
	}
}