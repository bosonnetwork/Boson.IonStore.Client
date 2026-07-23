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

import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.WriteStream;
import org.jspecify.annotations.Nullable;

import io.bosonnetwork.crypto.SecretStream;

/**
 * A Vert.x {@link WriteStream} wrapper that decrypts encrypted data and writes the
 * resulting plaintext to an underlying {@code WriteStream<Buffer>} using
 * {@link SecretStream.DecryptionStream}.
 * <p>
 * Accepts encrypted data (as produced by {@link EncryptedReadStream}), re-frames the
 * incoming buffers into SecretStream-compatible ciphertext blocks, decrypts each block,
 * and forwards the plaintext to the delegate {@link WriteStream}.
 * <p>
 * This class forms a symmetric pair with {@link EncryptedReadStream}:
 * <ul>
 *   <li>{@link EncryptedReadStream}: plaintext -> encrypted stream</li>
 *   <li>{@code DecryptedWriteStream}: encrypted stream -> plaintext</li>
 * </ul>
 * <p>
 * The encrypted stream format is:
 * <ol>
 *   <li>A {@link SecretStream#HEADER_BYTES}-byte header (24 bytes)</li>
 *   <li>Zero or more full encrypted chunks of {@code encryptedChunkSize} bytes (default 32 KiB)</li>
 *   <li>A final encrypted chunk that may be smaller than {@code encryptedChunkSize},
 *       carrying the {@code TAG_FINAL} marker</li>
 * </ol>
 */
public class DecryptedWriteStream implements WriteStream<Buffer> {
    /**
     * Default encrypted chunk size (32 KiB), matching the encrypted output chunk size
     * produced by {@link EncryptedReadStream} with its default configuration.
     */
    public static final int DEFAULT_ENCRYPTED_CHUNK_SIZE = 32 * 1024;

    private final WriteStream<Buffer> delegate;
    private final byte[] secretKey;
    private final int encryptedChunkSize;
    private final byte @Nullable [] additionalData;

    private Buffer accumulator = Buffer.buffer();
    @SuppressWarnings("NullAway.Init")
    private SecretStream.DecryptionStream decryptionStream;

    private @Nullable Handler<Throwable> exceptionHandler;

    private boolean headerParsed = false;
    private boolean terminated = false;
    private boolean complete = false;

    /**
     * Creates a {@code DecryptedWriteStream} wrapping a plaintext {@link WriteStream}.
     *
     * @param delegate           the plaintext output stream that receives decrypted data
     * @param secretKey          the 32-byte secret key for SecretStream decryption
     * @param encryptedChunkSize the size of a full encrypted ciphertext chunk; this must equal the
     *                           encrypting side's plain chunk size plus {@link SecretStream#ABYTES}
     *                           (the per-block auth tag overhead), otherwise the two sides re-frame
     *                           the stream differently and decryption fails authentication
     * @param additionalData     optional additional authenticated data (AAD), or {@code null}
     */
    public DecryptedWriteStream(WriteStream<Buffer> delegate, byte[] secretKey,
            int encryptedChunkSize, byte @Nullable [] additionalData) {
        this.delegate = Objects.requireNonNull(delegate, "delegate cannot be null");
        this.secretKey = Objects.requireNonNull(secretKey, "secretKey cannot be null");
        this.encryptedChunkSize = encryptedChunkSize;
        this.additionalData = additionalData;
    }

    /**
     * Creates a {@code DecryptedWriteStream} with default encrypted chunk size (32 KiB)
     * and no additional authenticated data.
     *
     * @param delegate  the plaintext output stream that receives decrypted data
     * @param secretKey the 32-byte secret key for SecretStream decryption
     */
    public DecryptedWriteStream(WriteStream<Buffer> delegate, byte[] secretKey) {
        this(delegate, secretKey, DEFAULT_ENCRYPTED_CHUNK_SIZE, null);
    }

    @Override
    public Future<Void> write(Buffer data) {
        if (terminated || complete) {
            return Future.failedFuture(new IllegalStateException("Stream is terminated or complete"));
        }

        accumulator.appendBuffer(data);

        try {
            // Parse header from the first bytes of the encrypted stream
            if (!headerParsed) {
                if (accumulator.length() < SecretStream.HEADER_BYTES) {
                    return Future.succeededFuture();
                }
                byte[] header = accumulator.getBytes(0, SecretStream.HEADER_BYTES);
                accumulator = accumulator.getBuffer(SecretStream.HEADER_BYTES, accumulator.length());
                decryptionStream = SecretStream.decryptionStream(header, secretKey);
                headerParsed = true;
            }

            // Process full encrypted chunks
            Future<Void> lastWrite = Future.succeededFuture();
            while (!complete && accumulator.length() >= encryptedChunkSize) {
                byte[] cipherBytes = accumulator.getBytes(0, encryptedChunkSize);
                accumulator = accumulator.getBuffer(encryptedChunkSize, accumulator.length());

                byte[] plainBytes = decryptionStream.pull(cipherBytes, additionalData);
                lastWrite = delegate.write(Buffer.buffer(plainBytes));

                if (decryptionStream.isComplete())
                    complete = true;
            }
            return lastWrite;
        } catch (Throwable t) {
            handleError(t);
            return Future.failedFuture(t);
        }
    }

    @Override
    public Future<Void> end() {
        if (terminated) {
            return Future.failedFuture(new IllegalStateException("Stream is terminated"));
        }

        try {
            // Process any remaining bytes as the final (shorter) encrypted chunk
            if (!complete && headerParsed && decryptionStream != null && accumulator.length() > 0) {
                byte[] cipherBytes = accumulator.getBytes();
                accumulator = Buffer.buffer();

                byte[] plainBytes = decryptionStream.pull(cipherBytes, additionalData);
                delegate.write(Buffer.buffer(plainBytes));

                complete = decryptionStream.isComplete();
            }

            // A well-formed stream always terminates by consuming a final block carrying the
            // TAG_FINAL marker. Reaching end() without having observed it means the stream was
            // truncated - cut at a chunk boundary, header-only, or missing its header entirely.
            // Reject it rather than silently accepting an unauthenticated prefix as complete plaintext.
            if (!complete) {
                throw new IllegalStateException(
                        "Encrypted stream is incomplete or truncated: final block marker not found");
            }

            closeStream();
            return delegate.end();
        } catch (Throwable t) {
            handleError(t);
            return Future.failedFuture(t);
        }
    }

    @Override
    public DecryptedWriteStream exceptionHandler(@Nullable Handler<Throwable> handler) {
        this.exceptionHandler = handler;
        delegate.exceptionHandler(handler);
        return this;
    }

    @Override
    public DecryptedWriteStream setWriteQueueMaxSize(int maxSize) {
        delegate.setWriteQueueMaxSize(maxSize);
        return this;
    }

    @Override
    public boolean writeQueueFull() {
        return delegate.writeQueueFull();
    }

    @Override
    public DecryptedWriteStream drainHandler(@Nullable Handler<Void> handler) {
        delegate.drainHandler(handler);
        return this;
    }

    private void handleError(Throwable t) {
        terminated = true;
        closeStream();
        if (exceptionHandler != null) {
            exceptionHandler.handle(t);
        }
    }

    private void closeStream() {
        try {
            if (decryptionStream != null) {
                decryptionStream.close();
            }
        } catch (Exception ignore) {}
    }
}