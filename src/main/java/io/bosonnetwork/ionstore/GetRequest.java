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

import java.io.OutputStream;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.WriteStream;
import org.jspecify.annotations.Nullable;

import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.SecretStream;
import io.bosonnetwork.vertx.ContextualFuture;

/**
 * A fluent retrieval request, created by {@link IonStore#get(Id)} or {@link IonStore#get(Id, Id)}.
 * <p>
 * Unlike {@link PutRequest}, a get has no terminal {@code send()}: naming the destination <em>is</em>
 * the terminal operation, because once the destination is known there is nothing left to configure.
 * Every {@code to*} method starts the transfer and returns a future carrying the destination's own
 * result type, so {@link #toBytes()} yields a {@link BytesIonObject} without a cast, and a request
 * with no destination cannot be expressed at all.
 * <p>
 * Anything that shapes the transfer - {@link #decrypt(byte[])}, {@link #raw()} - is therefore set
 * before the destination:
 * <pre>{@code
 * BytesIonObject obj = store.get(id).decrypt(key).toBytes().get().orElseThrow();
 * store.get(peerId, id).toFile(path);
 * }</pre>
 * <p>
 * Every destination is fed the integrity-verified payload: the bytes on the wire are hashed while
 * they stream and checked against the content id the service advertised. The check completes only
 * once the whole body has been transferred, so a destination that cannot be rolled back (an
 * {@link OutputStream}, a {@link WriteStream}) may already have received the corrupt bytes when the
 * returned future fails; {@link #toFile(Path)} deletes its file in that case.
 * <p>
 * A request is not bound to a single use: each {@code to*} call is an independent transfer. It is not
 * thread-safe, and {@link #decrypt(byte[])} must not be called concurrently with a transfer it is
 * meant to apply to.
 *
 * @see IonStore#get(Id)
 * @see PutRequest
 */
public class GetRequest {
	private final IonStore store;
	private final @Nullable Id peerId;
	private final Id id;

	private byte @Nullable [] decryptionKey;
	private boolean raw;

	GetRequest(IonStore store, @Nullable Id peerId, Id id) {
		this.store = store;
		this.peerId = peerId;
		this.id = id;
	}

	/**
	 * Decrypts the payload with the given key as it streams, so the destination receives plaintext.
	 * <p>
	 * The object must have been encrypted by {@link PutRequest#encrypt(byte[])} with the same key. How
	 * the ciphertext is framed is read from the object's own encryption descriptor rather than assumed,
	 * so an object stays readable after the client's defaults change.
	 * <p>
	 * The request and the object have to agree: retrieving an encrypted object without a key fails, and
	 * so does supplying a key for an object that is not encrypted. Neither mismatch is silently ignored,
	 * because either one would deliver bytes that are not what the caller asked for. Use {@link #raw()}
	 * to take the stored bytes without making a claim about them.
	 * <p>
	 * The key is copied, so the caller may reuse or clear the array immediately. Note that the object
	 * metadata still describes the stored (encrypted) form: {@link IonObject#isEncrypted()} is
	 * {@code true} and {@link IonObject#getSize()} is the ciphertext length. The length of what the
	 * destination actually receives is {@link IonObject#getPlainTextSize()}.
	 *
	 * @param decryptionKey the {@link SecretStream#KEY_BYTES}-byte key the object was encrypted with
	 *                      (must not be {@code null})
	 * @return this request
	 * @throws IllegalArgumentException if the key is not {@link SecretStream#KEY_BYTES} bytes long
	 * @throws IllegalStateException    if {@link #raw()} was already requested
	 */
	public GetRequest decrypt(byte[] decryptionKey) {
		Objects.requireNonNull(decryptionKey, "decryptionKey");
		if (decryptionKey.length != SecretStream.KEY_BYTES)
			throw new IllegalArgumentException("Invalid decryptionKey: expected a " + SecretStream.KEY_BYTES
					+ "-byte key, got " + decryptionKey.length + " bytes");
		if (raw)
			throw new IllegalStateException("decrypt() and raw() are mutually exclusive");

		this.decryptionKey = decryptionKey.clone();
		return this;
	}

	/**
	 * Retrieves the object exactly as it is stored, whatever that is: an encrypted object yields
	 * ciphertext rather than failing for want of a key.
	 * <p>
	 * This is for handling an object without reading it - caching it, relaying it, copying it to another
	 * store - and it is the only way to obtain an encrypted payload without holding the key. The bytes
	 * are still integrity-checked against the object's content id, which is computed over the stored
	 * form; what is skipped is decryption, not verification.
	 * <p>
	 * The ciphertext remains readable later: it carries its own framing, and the
	 * {@code Ion-Encryption} descriptor needed to decrypt it is part of the object metadata.
	 *
	 * @return this request
	 * @throws IllegalStateException if a decryption key was already supplied
	 */
	public GetRequest raw() {
		if (decryptionKey != null)
			throw new IllegalStateException("decrypt() and raw() are mutually exclusive");

		this.raw = true;
		return this;
	}

	/**
	 * Retrieves the object into memory.
	 *
	 * @return a future completing with the object and its payload, or an empty {@link Optional} if the
	 *         object was not found
	 */
	public ContextualFuture<Optional<BytesIonObject>> toBytes() {
		return ContextualFuture.of(store.getToBytes(peerId, id, decryptionKey, raw));
	}

	/**
	 * Retrieves the object into a buffer the caller supplies, appending to whatever it already holds.
	 * <p>
	 * This is the destination to use when assembling several payloads into one buffer; for the common
	 * case of reading a single object into memory, {@link #toBytes()} returns the payload with the
	 * metadata and needs no buffer. Only object metadata is returned here - the payload is in
	 * {@code buffer}, which the caller already has - so that there is never a second, ambiguous view of
	 * "the object's content" when the buffer holds more than this object.
	 *
	 * @param buffer the accumulator to append the payload to (must not be {@code null})
	 * @return a future completing with the object metadata, or an empty {@link Optional} if the object
	 *         was not found
	 */
	public ContextualFuture<Optional<IonObject>> toBuffer(Buffer buffer) {
		Objects.requireNonNull(buffer, "buffer");
		return ContextualFuture.of(store.getToBuffer(peerId, id, decryptionKey, raw, buffer));
	}

	/**
	 * Retrieves the object to a file, creating it or truncating it if it already exists.
	 * <p>
	 * The file is opened before the object is known to exist, and is deleted again if the object turns
	 * out to be missing or the transfer fails - so an existing file at this path is lost either way.
	 *
	 * @param file the destination file (must not be {@code null})
	 * @return a future completing with the object metadata, or an empty {@link Optional} if the object
	 *         was not found
	 */
	public ContextualFuture<Optional<IonObject>> toFile(Path file) {
		Objects.requireNonNull(file, "file");
		return ContextualFuture.of(store.getToFile(peerId, id, decryptionKey, raw, file));
	}

	/**
	 * Retrieves the object to a blocking {@link OutputStream}, written on a worker thread.
	 *
	 * @param stream      the destination stream (must not be {@code null})
	 * @param closeStream whether to close the stream when the transfer ends; if {@code false} the
	 *                    caller retains ownership and the stream is only flushed
	 * @return a future completing with the object metadata, or an empty {@link Optional} if the object
	 *         was not found
	 */
	public ContextualFuture<Optional<IonObject>> toOutputStream(OutputStream stream, boolean closeStream) {
		Objects.requireNonNull(stream, "stream");
		return ContextualFuture.of(store.getToOutputStream(peerId, id, decryptionKey, raw, stream, closeStream));
	}

	/**
	 * Retrieves the object to a blocking {@link OutputStream} the caller retains ownership of (see
	 * {@link #toOutputStream(OutputStream, boolean)}).
	 *
	 * @param stream the destination stream (must not be {@code null})
	 * @return a future completing with the object metadata, or an empty {@link Optional} if the object
	 *         was not found
	 */
	public ContextualFuture<Optional<IonObject>> toOutputStream(OutputStream stream) {
		return toOutputStream(stream, false);
	}

	/**
	 * Retrieves the object to a Vert.x {@link WriteStream}, which is ended when the transfer completes.
	 *
	 * @param stream the destination stream (must not be {@code null})
	 * @return a future completing with the object metadata, or an empty {@link Optional} if the object
	 *         was not found
	 */
	public ContextualFuture<Optional<IonObject>> toWriteStream(WriteStream<Buffer> stream) {
		Objects.requireNonNull(stream, "stream");
		return ContextualFuture.of(store.getToWriteStream(peerId, id, decryptionKey, raw, stream));
	}
}
