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

import java.io.InputStream;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;
import org.jspecify.annotations.Nullable;

import io.bosonnetwork.crypto.SecretStream;
import io.bosonnetwork.vertx.ContextualFuture;

/**
 * A fluent, single-use description of one {@link IonStore} put: where the payload comes from, how it
 * should be described to the service, and whether it is encrypted on the way out.
 * <p>
 * Obtain one from {@link IonStore#put()}, configure it, then call {@link #send()}:
 * <pre>{@code
 * ionStore.put()
 *         .name("photo.jpg")
 *         .contentType("image/jpeg")
 *         .content(pathToImageFile)
 *         .send();
 * }</pre>
 * Exactly one {@code content(...)} call decides the payload source; a later call replaces an earlier
 * one. Every other setter is optional and order-independent. Not thread-safe.
 *
 * <h2>Payload ownership</h2>
 * A put is asynchronous, and the payload is generally <em>not</em> copied - it is read as the upload
 * streams, so that a large payload does not cost a second copy in memory. The caller must therefore
 * leave the object passed to {@code content(...)} alone until the future returned by {@link #send()}
 * completes: do not modify the array or buffer, do not read from or close the stream, and do not
 * replace the file. The per-source notes on each {@code content(...)} overload spell out who closes
 * what.
 *
 * <h2>Custom metadata</h2>
 * Metadata supplied via {@link #metadata(String, Object)} is transmitted as {@code Ion-*} request
 * headers; a key that does not already start with {@code Ion-} is prefixed automatically. Because
 * metadata travels in headers it must be ASCII and kept small (the combined {@code Ion-*} headers
 * should stay within ~8&nbsp;KB). The names {@code Ion-TTL}, {@code Ion-Encrypted},
 * {@code Ion-Expire-At}, {@code Ion-Content-Id} and {@code Ion-Encryption} are managed for you and
 * are ignored if supplied as custom metadata.
 *
 * <h2>Reuse</h2>
 * {@link #send()} snapshots the request, so mutating it afterwards cannot disturb an upload already
 * in flight. It does <em>not</em> make the request replayable: a stream source is consumed by the
 * first send, and an encrypted put is randomised, so re-sending produces a different object rather
 * than a retry of the first (see {@link IonStore}'s encryption notes).
 *
 * @see IonStore#put()
 */
public class PutRequest {
	private final IonStore store;

	private @Nullable String name;
	private long contentLength;
	private @Nullable String contentType;
	private long ttl;
	private final Map<String, Object> metadata;

	private byte @Nullable [] encryptionKey;

	private @Nullable Object content;
	private ContentSource contentSource;

	private boolean closeContent;

	enum ContentSource { EMPTY, BYTES, BUFFER, FILE, INPUT_STREAM, READ_STREAM }

	PutRequest(IonStore store) {
		this.store = store;
		this.metadata = new LinkedHashMap<>();
		this.contentSource = ContentSource.EMPTY;
		this.closeContent = false;
	}

	private PutRequest(PutRequest other) {
		this.store = other.store;
		this.name = other.name;
		this.contentLength = other.contentLength;
		this.contentType = other.contentType;
		this.ttl = other.ttl;
		this.metadata = new LinkedHashMap<>(other.metadata);
		this.encryptionKey = other.encryptionKey;
		this.content = other.content;
		this.contentSource = other.contentSource;
		this.closeContent = other.closeContent;
	}

	/**
	 * Sets the logical file name.
	 *
	 * @param name the file name
	 * @return this request
	 */
	public PutRequest name(String name) {
		this.name = name;
		return this;
	}

	@Nullable String name() {
		return name;
	}

	/**
	 * Declares the payload length in bytes, letting the upload be sent with a {@code Content-Length}
	 * instead of chunked transfer encoding. {@code 0} (the default) means "unknown" and sends chunked.
	 * <p>
	 * This applies only to the {@link #content(InputStream) InputStream} and
	 * {@link #content(ReadStream) ReadStream} sources, whose length cannot be discovered up front.
	 * The array, buffer and file sources measure themselves and ignore any value set here.
	 * <p>
	 * Declare the <em>plaintext</em> length even when the put is {@linkplain #encrypt(byte[])
	 * encrypted}; the ciphertext expansion is accounted for automatically. An inaccurate value breaks
	 * the request, so leave it unset rather than guess.
	 *
	 * @param contentLength the payload length in bytes; {@code 0} or negative means unknown
	 * @return this request
	 */
	public PutRequest contentLength(long contentLength) {
		this.contentLength = contentLength > 0 ? contentLength : 0;
		return this;
	}

	long contentLength() {
		return contentLength;
	}

	/**
	 * Sets the MIME content type.
	 *
	 * @param contentType the content type
	 * @return this request
	 */
	public PutRequest contentType(String contentType) {
		this.contentType = contentType;
		return this;
	}

	@Nullable String contentType() {
		return contentType;
	}

	/**
	 * Sets the requested object lifetime in seconds. {@code 0} (the default) uses the server
	 * default lifetime.
	 *
	 * @param ttlSeconds the lifetime in seconds (must be {@code >= 0})
	 * @return this request
	 * @throws IllegalArgumentException if {@code ttlSeconds} is negative
	 */
	public PutRequest ttl(long ttlSeconds) {
		if (ttlSeconds < 0)
			throw new IllegalArgumentException("ttl must be >= 0");
		this.ttl = ttlSeconds;
		return this;
	}

	long ttl() {
		return ttl;
	}

	/**
	 * Encrypts the payload client-side with the given key, so the service only ever sees ciphertext.
	 * <p>
	 * The payload is encrypted as it streams; the key never leaves the client. The stored object is
	 * flagged {@code Ion-Encrypted} and carries an {@code Ion-Encryption} descriptor recording the
	 * scheme and chunk size, so it stays decryptable even if the client's defaults change later.
	 * Ciphertext is slightly larger than its plaintext - see
	 * {@link EncryptedReadStream#getCipherTextSize(long, int)}.
	 * <p>
	 * The key is small and fixed-size, so it is copied defensively: the caller may reuse or wipe
	 * {@code encryptionKey} as soon as this method returns. That is the opposite of the payload
	 * itself, which is <em>not</em> copied (see {@link #content(byte[])}).
	 * <p>
	 * Encryption is randomised, so the same plaintext yields a different object on every put and
	 * cannot be deduplicated by the service. See {@link IonStore} for what that implies for retries
	 * and quota.
	 *
	 * @param encryptionKey the secret key, exactly {@link SecretStream#KEY_BYTES} bytes (must not be
	 *                      {@code null})
	 * @return this request
	 * @throws NullPointerException     if {@code encryptionKey} is {@code null}
	 * @throws IllegalArgumentException if {@code encryptionKey} is not
	 *                                  {@link SecretStream#KEY_BYTES} bytes long
	 */
	public PutRequest encrypt(byte[] encryptionKey) {
		Objects.requireNonNull(encryptionKey, "encryptionKey cannot be null");
		if (encryptionKey.length != SecretStream.KEY_BYTES)
			throw new IllegalArgumentException("Invalid encryptionKey: expected a " + SecretStream.KEY_BYTES
					+ "-byte key, got " + encryptionKey.length + " bytes");

		this.encryptionKey = encryptionKey.clone();
		return this;
	}

	boolean isEncrypted() {
		return encryptionKey != null;
	}

	byte @Nullable [] encryptionKey() {
		return encryptionKey;
	}

	/**
	 * Adds a single custom metadata entry. A key that does not already start with {@code Ion-} is
	 * prefixed with it at send time.
	 *
	 * @param key   the metadata key (must not be {@code null})
	 * @param value the metadata value (must not be {@code null})
	 * @return this request
	 */
	public PutRequest metadata(String key, Object value) {
		Objects.requireNonNull(key, "key");
		Objects.requireNonNull(value, "value");
		this.metadata.put(key, value);
		return this;
	}

	/**
	 * Adds all entries from the given metadata map.
	 *
	 * @param metadata the metadata entries (must not be {@code null})
	 * @return this request
	 */
	public PutRequest metadata(Map<String, Object> metadata) {
		Objects.requireNonNull(metadata, "metadata");
		metadata.forEach(this::metadata);
		return this;
	}

	Map<String, Object> metadata() {
		return Collections.unmodifiableMap(metadata);
	}

	/**
	 * Sets the payload to the given byte array.
	 * <p>
	 * Small payloads are copied up front, but larger ones are read from {@code content} as the upload
	 * streams - copying a large array would double its memory cost for no benefit. The caller must
	 * therefore not modify {@code content} until the future returned by {@link #send()} completes.
	 *
	 * @param content the object payload (must not be {@code null})
	 * @return this request
	 */
	public PutRequest content(byte[] content) {
		Objects.requireNonNull(content, "content");
		contentSource = ContentSource.BYTES;
		this.content = content;
		return this;
	}

	/**
	 * Sets the payload to the given buffer.
	 * <p>
	 * As with {@link #content(byte[])}, a large buffer is read as the upload streams rather than
	 * copied, so the caller must not modify {@code content} until the future returned by
	 * {@link #send()} completes.
	 *
	 * @param content the object payload (must not be {@code null})
	 * @return this request
	 */
	public PutRequest content(Buffer content) {
		Objects.requireNonNull(content, "content");
		contentSource = ContentSource.BUFFER;
		this.content = content;
		return this;
	}

	/**
	 * Sets the payload to the contents of a file, streamed from disk.
	 * <p>
	 * The file is opened when {@link #send()} is called and closed when the upload settles. If no
	 * {@linkplain #name(String) name} or {@linkplain #contentType(String) content type} has been set,
	 * they default to the file's name and its probed MIME type. The file must not be modified or
	 * removed while the upload is in flight - its size is measured up front to declare a
	 * {@code Content-Length}, and a file that changes underneath will break the request.
	 *
	 * @param file the file to store (must not be {@code null})
	 * @return this request
	 */
	public PutRequest content(Path file) {
		Objects.requireNonNull(file, "file");
		contentSource = ContentSource.FILE;
		this.content = file;
		return this;
	}

	/**
	 * Sets the payload to a blocking {@link InputStream}, read on a worker thread.
	 * <p>
	 * The stream's length is not known in advance, so the upload is sent chunked unless
	 * {@link #contentLength(long)} declares it.
	 *
	 * @param content      the object payload (must not be {@code null})
	 * @param closeContent {@code true} to close {@code content} once the upload ends, fails, or is
	 *                     cancelled; {@code false} to leave it open, in which case the caller retains
	 *                     ownership and must close it after {@link #send()} completes
	 * @return this request
	 */
	public PutRequest content(InputStream content, boolean closeContent) {
		Objects.requireNonNull(content, "content");
		contentSource = ContentSource.INPUT_STREAM;
		this.content = content;
		this.closeContent = closeContent;
		return this;
	}

	/**
	 * Sets the payload to a blocking {@link InputStream} that this request will <b>not</b> close: the
	 * caller retains ownership and must close it once {@link #send()} completes.
	 *
	 * @param content the object payload (must not be {@code null})
	 * @return this request
	 * @see #content(InputStream, boolean)
	 */
	public PutRequest content(InputStream content) {
		return content(content, false);
	}

	/**
	 * Sets the payload to a Vert.x {@link ReadStream}.
	 * <p>
	 * The stream is consumed by {@link #send()} and is not closed by this request. Its length is not
	 * known in advance, so the upload is sent chunked unless {@link #contentLength(long)} declares it.
	 *
	 * @param content the object payload (must not be {@code null})
	 * @return this request
	 */
	public PutRequest content(ReadStream<Buffer> content) {
		Objects.requireNonNull(content, "content");
		contentSource = ContentSource.READ_STREAM;
		this.content = content;
		return this;
	}

	boolean closeContent() {
		return closeContent;
	}

	ContentSource contentSource() {
		return contentSource;
	}

	@SuppressWarnings("unchecked")
	<T> T content() {
		return (T) Objects.requireNonNull(content);
	}

	/**
	 * Sends the put and completes with the stored object's metadata.
	 * <p>
	 * The request is snapshotted first, so mutating it afterwards cannot disturb an upload in flight.
	 * The payload source is not snapshotted and must be left alone until the returned future
	 * completes - see the ownership notes on {@link PutRequest} and each {@code content(...)}
	 * overload.
	 *
	 * @return a future completing with the stored object's metadata
	 * @throws IllegalStateException if no content source was set, or the client is closed
	 */
	public ContextualFuture<IonObject> send() {
		if (contentSource == ContentSource.EMPTY)
			throw new IllegalStateException("No content provided");

		return store.put(this);
	}

	PutRequest dup() {
		return new PutRequest(this);
	}
}
