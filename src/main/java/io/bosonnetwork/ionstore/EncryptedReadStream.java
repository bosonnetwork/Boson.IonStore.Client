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

import java.util.Objects;

import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;
import org.jspecify.annotations.Nullable;

import io.bosonnetwork.crypto.SecretStream;

/**
 * A Vert.x {@link ReadStream} wrapper that encrypts plain data chunks from an underlying
 * {@code ReadStream<Buffer>} using {@link SecretStream.EncryptionStream}.
 * <p>
 * Slices arbitrary incoming buffers into fixed-size plain chunks, encrypts each chunk,
 * and yields the stream header followed by encrypted {@link Buffer}s.
 */
public class EncryptedReadStream implements ReadStream<Buffer> {
	/**
	 * Default plain chunk size (32 KiB minus SecretStream tag overhead of 17 bytes).
	 * Pushing a plain chunk of this size produces an encrypted ciphertext block of exactly 32 KiB.
	 */
	public static final int DEFAULT_CHUNK_SIZE = 32 * 1024 - SecretStream.ABYTES;

	private final ReadStream<Buffer> delegate;
	private final SecretStream.EncryptionStream encryptionStream;
	private final int chunkSize;
	private final byte @Nullable [] additionalData;

	private Buffer accumulator = Buffer.buffer();

	private @Nullable Handler<Buffer> dataHandler;
	private @Nullable Handler<Throwable> exceptionHandler;
	private @Nullable Handler<Void> endHandler;

	private boolean headerSent = false;
	private boolean terminated = false;

	/**
	 * Creates an {@code EncryptedReadStream} wrapping a plain {@link ReadStream}.
	 *
	 * @param delegate       the plain input stream
	 * @param secretKey      the 32-byte secret key for SecretStream
	 * @param chunkSize      plain chunk size before encryption; a non-positive value falls back to
	 *                       {@link #DEFAULT_CHUNK_SIZE}
	 * @param additionalData optional additional authenticated data (AAD), or {@code null}
	 * @throws NullPointerException     if {@code delegate} or {@code secretKey} is {@code null}
	 * @throws IllegalArgumentException if {@code secretKey} is not {@link SecretStream#KEY_BYTES} bytes long
	 */
	public EncryptedReadStream(ReadStream<Buffer> delegate, byte[] secretKey, int chunkSize, byte @Nullable [] additionalData) {
		this.delegate = Objects.requireNonNull(delegate, "delegate cannot be null");
		this.encryptionStream = SecretStream.encryptionStream(secretKey);
		this.chunkSize = chunkSize > 0 ? chunkSize : DEFAULT_CHUNK_SIZE;
		this.additionalData = additionalData;
	}

	/**
	 * Creates an {@code EncryptedReadStream} using the {@link #DEFAULT_CHUNK_SIZE default plain chunk
	 * size} and no additional authenticated data.
	 *
	 * @param delegate  the plain input stream
	 * @param secretKey the 32-byte secret key for SecretStream
	 * @throws NullPointerException     if {@code delegate} or {@code secretKey} is {@code null}
	 * @throws IllegalArgumentException if {@code secretKey} is not {@link SecretStream#KEY_BYTES} bytes long
	 */
	public EncryptedReadStream(ReadStream<Buffer> delegate, byte[] secretKey) {
		this(delegate, secretKey, DEFAULT_CHUNK_SIZE, null);
	}

	@Override
	public EncryptedReadStream handler(@Nullable Handler<Buffer> handler) {
		this.dataHandler = handler;
		if (handler == null) {
			delegate.handler(null);
			return this;
		}

		delegate.handler(buffer -> {
			if (terminated) return;

			try {
				// Emit stream header as the first chunk downstream
				if (!headerSent) {
					headerSent = true;
					handler.handle(Buffer.buffer(encryptionStream.header()));
				}

				accumulator.appendBuffer(buffer);

				// Process full fixed-size chunks
				while (accumulator.length() >= chunkSize) {
					byte[] chunkBytes = accumulator.getBytes(0, chunkSize);
					accumulator = accumulator.getBuffer(chunkSize, accumulator.length());

					byte[] cipherBytes = encryptionStream.push(chunkBytes, additionalData, false);
					handler.handle(Buffer.buffer(cipherBytes));
				}
			} catch (Throwable t) {
				handleError(t);
			}
		});

		delegate.endHandler(v -> {
			if (terminated) return;

			try {
				// Ensure header was emitted even if input stream was empty
				if (!headerSent && dataHandler != null) {
					headerSent = true;
					dataHandler.handle(Buffer.buffer(encryptionStream.header()));
				}

				// Push final block (even if empty)
				byte[] remainingPlain = accumulator.getBytes();
				byte[] finalCipherBytes = encryptionStream.pushLast(remainingPlain, additionalData);

				if (dataHandler != null && finalCipherBytes.length > 0) {
					dataHandler.handle(Buffer.buffer(finalCipherBytes));
				}

				closeStream();

				if (endHandler != null) {
					endHandler.handle(null);
				}
			} catch (Throwable t) {
				handleError(t);
			}
		});

		return this;
	}

	@Override
	public EncryptedReadStream exceptionHandler(@Nullable Handler<Throwable> handler) {
		this.exceptionHandler = handler;
		delegate.exceptionHandler(t -> {
			closeStream();
			if (exceptionHandler != null) {
				exceptionHandler.handle(t);
			}
		});
		return this;
	}

	@Override
	public EncryptedReadStream endHandler(@Nullable Handler<Void> handler) {
		this.endHandler = handler;
		return this;
	}

	@Override
	public EncryptedReadStream pause() {
		delegate.pause();
		return this;
	}

	@Override
	public EncryptedReadStream resume() {
		if (!terminated) {
			delegate.resume();
		}
		return this;
	}

	@Override
	public EncryptedReadStream fetch(long amount) {
		if (!terminated) {
			delegate.fetch(amount);
		}
		return this;
	}

	private void handleError(Throwable t) {
		terminated = true;
		delegate.pause();
		closeStream();
		if (exceptionHandler != null) {
			exceptionHandler.handle(t);
		}
	}

	private void closeStream() {
		try {
			encryptionStream.close();
		} catch (Exception ignore) {
		}
	}
}