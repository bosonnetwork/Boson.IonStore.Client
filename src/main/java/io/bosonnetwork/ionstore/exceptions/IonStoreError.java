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

package io.bosonnetwork.ionstore.exceptions;

/**
 * The error categories the Ion Store service can report.
 * <p>
 * This is an internal mapping table: every error response from the service carries a {@code type}
 * (this category's {@linkplain #name() name}) and a stable numeric {@code code}, which
 * {@link IonStoreException#fromResponse(int, io.vertx.core.buffer.Buffer)} uses to select the
 * corresponding public exception subclass (for example {@link FORBIDDEN} &rarr;
 * {@link ForbiddenException}). The category itself is not part of the public API — callers branch on
 * the exception type instead.
 * <p>
 * The set mirrors the service's own error catalogue. Should a newer service report a category this
 * client does not know, it is resolved to {@link #UNKNOWN}, and the failure surfaces as a plain
 * {@link IonStoreException} whose original numeric code is still preserved via
 * {@link IonStoreException#getErrorCode()}.
 */
enum IonStoreError {
	/** Missing or invalid CWT bearer token; HTTP {@code 401}. The credentials need to be corrected. */
	UNAUTHORIZED(1, "Unauthorized"),
	/** The request is not permitted; HTTP {@code 403}. */
	FORBIDDEN(2, "Forbidden"),
	/** Malformed request, invalid object id, or invalid pagination parameter; HTTP {@code 400}. */
	INVALID_REQUEST(3, "Invalid request"),
	/** The payload exceeds the service's configured maximum object size; HTTP {@code 413}. */
	OBJECT_TOO_LARGE(4, "Object size limit exceeded"),
	/** The user's storage quota is exhausted; HTTP {@code 429}. Free space or retry later. */
	QUOTA_EXCEEDED(5, "Quota limit exceeded"),
	/** The requested {@code Ion-TTL} exceeds the service's configured maximum lifetime; HTTP {@code 403}. */
	TTL_EXCEEDED(6, "TTL limit exceeded"),
	/** No object exists for the given reference id; HTTP {@code 404}. */
	OBJECT_NOT_FOUND(7, "Object not found"),

	/** The service encountered an I/O error while serving the request. */
	IO_ERROR(8, "IO error"),
	/** The service's metadata store failed. */
	METABASE_ERROR(9, "Metabase error"),
	/** A generic, unclassified server-side failure. */
	SERVER_ERROR(10, "Server error"),
	/** The service detected an object-integrity failure on its side. */
	INTEGRITY_ERROR(11, "Object integrity error"),

	/** The federation peer that should hold the object could not be located. */
	PEER_NOT_FOUND(61, "Peer not found"),
	/** The service failed to issue the federated request to the peer. */
	PEER_REQUEST_ERROR(62, "Peer request error"),
	/** The federation peer returned an error response (see the nested detail on the exception). */
	PEER_RESPONSE_ERROR(63, "Peer response error"),

	/** An internal service error with no more specific category. */
	INTERNAL_ERROR(255, "Ion Store internal error"),

	/**
	 * Sentinel for a category this client does not recognize (for example, one introduced by a newer
	 * service). The original numeric code is still available via {@link IonStoreException#getErrorCode()}.
	 */
	UNKNOWN(-1, "Unknown error");

	private final int code;
	private final String defaultMessage;

	IonStoreError(int code, String defaultMessage) {
		this.code = code;
		this.defaultMessage = defaultMessage;
	}

	/**
	 * Returns the stable numeric code the service associates with this category.
	 *
	 * @return the numeric error code, or {@code -1} for {@link #UNKNOWN}
	 */
	public int getCode() {
		return code;
	}

	/**
	 * Returns a short, human-readable description of this category, used as a fallback when the
	 * service does not supply a message of its own.
	 *
	 * @return the default message for this category
	 */
	public String getDefaultMessage() {
		return defaultMessage;
	}

	/**
	 * Resolves an error category from the {@code type} and {@code code} fields of a service error
	 * response, preferring the (more descriptive) {@code type} name and falling back to the numeric
	 * {@code code}. Unrecognized values resolve to {@link #UNKNOWN}.
	 *
	 * @param type the {@code type} field, or {@code null} if absent
	 * @param code the {@code code} field
	 * @return the matching category, or {@link #UNKNOWN} if neither field is recognized
	 */
	public static IonStoreError resolve(String type, int code) {
		if (type != null && !type.isEmpty()) {
			try {
				return valueOf(type);
			} catch (IllegalArgumentException ignore) {
				// fall through to code-based lookup
			}
		}
		return fromCode(code);
	}

	/**
	 * Returns the category with the given numeric code, or {@link #UNKNOWN} if none matches.
	 *
	 * @param code the numeric error code
	 * @return the matching category, or {@link #UNKNOWN}
	 */
	public static IonStoreError fromCode(int code) {
		for (IonStoreError e : values()) {
			if (e != UNKNOWN && e.code == code)
				return e;
		}
		return UNKNOWN;
	}
}