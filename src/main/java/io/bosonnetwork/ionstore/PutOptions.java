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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NullUnmarked;

/**
 * Options for an {@link IonStore} put: the logical file name, content type, lifetime, encryption
 * flag and any custom {@code Ion-*} metadata.
 * <p>
 * All fields are optional. Obtain an instance through {@link #builder()}, or {@link #none()} for a
 * put with no options. Instances are immutable.
 *
 * <h2>Custom metadata</h2>
 * Metadata supplied via {@link Builder#metadata} is transmitted as {@code Ion-*} request headers; a
 * key that does not already start with {@code Ion-} is prefixed automatically. Because metadata
 * travels in headers it must be ASCII and kept small (the combined {@code Ion-*} headers should stay
 * within ~8&nbsp;KB). The reserved names {@code Ion-TTL}, {@code Ion-Encrypted}, {@code Ion-Expire-At}
 * and {@code Ion-Content-Id} are server-managed and cannot be used as custom metadata.
 */
@NullUnmarked
public class PutOptions {
	private static final PutOptions NONE = builder().build();

	private final String name;
	private final String contentType;
	private final long ttl;
	private final boolean encrypted;
	private final Map<String, Object> metadata;

	private PutOptions(Builder builder) {
		this.name = builder.name;
		this.contentType = builder.contentType;
		this.ttl = builder.ttl;
		this.encrypted = builder.encrypted;
		this.metadata = builder.metadata.isEmpty() ?
				Collections.emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(builder.metadata));
	}

	/**
	 * Returns a shared, empty options instance (no name, no metadata, no TTL, not encrypted).
	 *
	 * @return the empty options instance
	 */
	public static PutOptions none() {
		return NONE;
	}

	/**
	 * Returns the logical file name, or {@code null} if none was set.
	 *
	 * @return the file name, or {@code null}
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the MIME content type, or {@code null} if none was set.
	 *
	 * @return the content type, or {@code null}
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Returns the requested object lifetime in seconds, or {@code 0} to use the server default. The
	 * effective lifetime is capped by the service's configured maximum.
	 *
	 * @return the TTL in seconds, or {@code 0}
	 */
	public long getTtl() {
		return ttl;
	}

	/**
	 * Indicates whether the payload should be flagged as client-side encrypted (informational only).
	 *
	 * @return {@code true} if the encryption flag should be set
	 */
	public boolean isEncrypted() {
		return encrypted;
	}

	/**
	 * Returns the custom metadata as an unmodifiable map (empty if none). Keys are returned as
	 * supplied (without the automatic {@code Ion-} prefix applied at send time).
	 *
	 * @return an unmodifiable metadata map
	 */
	public Map<String, Object> getMetadata() {
		return metadata;
	}

	/**
	 * Creates a new {@link Builder}.
	 *
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Fluent builder for {@link PutOptions}. Not thread-safe.
	 */
	public static class Builder {
		private String name;
		private String contentType;
		private long ttl;
		private boolean encrypted;
		private final Map<String, Object> metadata = new LinkedHashMap<>();

		private Builder() {
		}

		/**
		 * Sets the logical file name.
		 *
		 * @param name the file name
		 * @return this builder
		 */
		public Builder name(String name) {
			this.name = name;
			return this;
		}

		/**
		 * Sets the MIME content type.
		 *
		 * @param contentType the content type
		 * @return this builder
		 */
		public Builder contentType(String contentType) {
			this.contentType = contentType;
			return this;
		}

		/**
		 * Sets the requested object lifetime in seconds. {@code 0} (the default) uses the server
		 * default lifetime.
		 *
		 * @param ttlSeconds the lifetime in seconds (must be {@code >= 0})
		 * @return this builder
		 * @throws IllegalArgumentException if {@code ttlSeconds} is negative
		 */
		public Builder ttl(long ttlSeconds) {
			if (ttlSeconds < 0)
				throw new IllegalArgumentException("ttl must be >= 0");
			this.ttl = ttlSeconds;
			return this;
		}

		/**
		 * Sets the client-side-encrypted flag.
		 *
		 * @param encrypted {@code true} to flag the object as encrypted
		 * @return this builder
		 */
		public Builder encrypted(boolean encrypted) {
			this.encrypted = encrypted;
			return this;
		}

		/**
		 * Adds a single custom metadata entry. A key that does not already start with {@code Ion-} is
		 * prefixed with it at send time.
		 *
		 * @param key   the metadata key (must not be {@code null})
		 * @param value the metadata value (must not be {@code null})
		 * @return this builder
		 */
		public Builder metadata(String key, Object value) {
			Objects.requireNonNull(key, "key");
			Objects.requireNonNull(value, "value");
			this.metadata.put(key, value);
			return this;
		}

		/**
		 * Adds all entries from the given metadata map.
		 *
		 * @param metadata the metadata entries (must not be {@code null})
		 * @return this builder
		 */
		public Builder metadata(Map<String, Object> metadata) {
			Objects.requireNonNull(metadata, "metadata");
			metadata.forEach(this::metadata);
			return this;
		}

		/**
		 * Builds the immutable {@link PutOptions}.
		 *
		 * @return the upload options
		 */
		public PutOptions build() {
			return new PutOptions(this);
		}
	}
}