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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import io.vertx.core.json.JsonObject;

import io.bosonnetwork.Id;

/**
 * Metadata describing a single object reference in an Ion Store, as returned by the service.
 * <p>
 * An object carries two distinct ids that are easy to confuse:
 * <ul>
 *   <li>{@link #getId()} &mdash; the <b>reference id</b>: a random per-reference id used to address
 *       the object (the value embedded in {@code ions://} URIs); and</li>
 *   <li>{@link #getContentId()} &mdash; the <b>content id</b>: the SHA-256 of the bytes, used for
 *       integrity verification and server-side deduplication. Several references may share one
 *       content id.</li>
 * </ul>
 *
 * <p>Instances come from {@link IonStore#getIonObject(Id)}, {@link IonStore#list(long, long)} and the
 * {@code put}/{@code get} operations. A metadata instance derived from the headers of a payload
 * retrieval may have a {@code null} {@link #getName() name} or {@link #getContentType() contentType}
 * if the service did not advertise them.
 */
public class IonObject {
	private final Id id;
	private final Id contentId;
	private final String name;
	private final long size;
	private final String contentType;
	private final boolean encrypted;
	private final long expireAt;
	private final Map<String, Object> metadata;
	private final String uri;

	/**
	 * Creates an object metadata instance.
	 *
	 * @param id          the reference id used to address the object
	 * @param contentId   the SHA-256 content id of the payload
	 * @param name        the logical file name, or {@code null}
	 * @param size        the payload size in bytes
	 * @param contentType the MIME content type, or {@code null}
	 * @param encrypted   {@code true} if the object is flagged client-side encrypted
	 * @param expireAt    expiry time as epoch seconds; {@code 0} if the object never expires
	 * @param metadata    custom {@code Ion-*} metadata, or {@code null} for none
	 * @param uri         the {@code ions://<peerId>/<id>} address of the object, or {@code null}
	 */
	public IonObject(Id id, Id contentId, String name, long size, String contentType, boolean encrypted,
	                 long expireAt, Map<String, Object> metadata, String uri) {
		this.id = id;
		this.contentId = contentId;
		this.name = name;
		this.size = size;
		this.contentType = contentType;
		this.encrypted = encrypted;
		this.expireAt = expireAt;
		this.metadata = metadata == null || metadata.isEmpty() ?
				Collections.emptyMap() : Collections.unmodifiableMap(metadata);
		this.uri = uri;
	}

	/**
	 * Returns the reference id &mdash; the random, per-reference id used to address this object.
	 *
	 * @return the reference id
	 */
	public Id getId() {
		return id;
	}

	/**
	 * Returns the content id &mdash; the SHA-256 of the object's bytes, used for integrity
	 * verification and deduplication.
	 *
	 * @return the content id
	 */
	public Id getContentId() {
		return contentId;
	}

	/**
	 * Returns the logical file name, or {@code null} if none was supplied.
	 *
	 * @return the file name, or {@code null}
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the payload size in bytes.
	 *
	 * @return the size in bytes
	 */
	public long getSize() {
		return size;
	}

	/**
	 * Returns the MIME content type, or {@code null} if none was supplied.
	 *
	 * @return the content type, or {@code null}
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Indicates whether the object is flagged as client-side encrypted. This is metadata only; the
	 * store never encrypts or decrypts content.
	 *
	 * @return {@code true} if the object is flagged encrypted
	 */
	public boolean isEncrypted() {
		return encrypted;
	}

	/**
	 * Returns the expiry time as epoch seconds, or {@code 0} if the object never expires.
	 *
	 * @return the expiry time in epoch seconds, or {@code 0} for never
	 */
	public long getExpireAt() {
		return expireAt;
	}

	/**
	 * Returns the custom {@code Ion-*} metadata as an unmodifiable map (empty if none).
	 *
	 * @return an unmodifiable metadata map
	 */
	public Map<String, Object> getMetadata() {
		return metadata;
	}

	/**
	 * Returns the {@code ions://<peerId>/<id>} address of the object, or {@code null} if unknown.
	 *
	 * @return the object URI, or {@code null}
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Parses an {@link IonObject} from the service's JSON representation (the OpenAPI
	 * {@code IonObject} schema).
	 *
	 * @param json the JSON object returned by the service
	 * @return the parsed metadata
	 * @throws IllegalArgumentException if a required field is missing or malformed
	 */
	public static IonObject fromJson(JsonObject json) {
		Objects.requireNonNull(json, "json");

		Id id = Id.of(json.getString("id"));
		Id contentId = Id.of(json.getString("contentId"));
		String name = json.getString("name");
		long size = json.getLong("size", 0L);
		String contentType = json.getString("contentType");
		boolean encrypted = json.getBoolean("encrypted", false);
		long expireAt = json.getLong("expireAt", 0L);
		String uri = json.getString("uri");

		// Preserve the metadata values as-is (the service models metadata as Map<String, Object>).
		JsonObject meta = json.getJsonObject("metadata");
		Map<String, Object> metadata = meta == null ? null : new HashMap<>(meta.getMap());

		return new IonObject(id, contentId, name, size, contentType, encrypted, expireAt, metadata, uri);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, contentId, name, size, contentType, encrypted, expireAt, metadata, uri);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;

		if (obj instanceof IonObject that)
			return size == that.size &&
					encrypted == that.encrypted &&
					expireAt == that.expireAt &&
					Objects.equals(id, that.id) &&
					Objects.equals(contentId, that.contentId) &&
					Objects.equals(name, that.name) &&
					Objects.equals(contentType, that.contentType) &&
					metadata.equals(that.metadata) &&
					Objects.equals(uri, that.uri);

		return false;
	}

	@Override
	public String toString() {
		StringBuilder repr = new StringBuilder("IonObject[");
		repr.append("id=").append(id)
				.append(", contentId=").append(contentId);
		if (name != null)
			repr.append(", name=").append(name);
		repr.append(", size=").append(size);
		if (contentType != null)
			repr.append(", contentType=").append(contentType);
		if (encrypted)
			repr.append(", encrypted");
		repr.append(", expireAt=").append(expireAt);
		if (!metadata.isEmpty())
			repr.append(", metadata=").append(metadata);
		if (uri != null)
			repr.append(", uri=").append(uri);
		repr.append(']');
		return repr.toString();
	}
}