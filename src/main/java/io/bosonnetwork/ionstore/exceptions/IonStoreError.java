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
 * The set mirrors the service's own error catalogue, which is the canonical specification; the two
 * copies (one here, one in the service) must be kept in lock-step on every {@code (name, code)} pair.
 * Codes are banded by concern: {@code 10–19} request/auth, {@code 20–29} object state/limits,
 * {@code 40–49} federation, {@code 50–99} server-side. Should a newer service report a category this
 * client does not know, it is resolved to {@link #UNKNOWN}, and the failure surfaces as a plain
 * {@link IonStoreException} whose original numeric code is still preserved via
 * {@link IonStoreException#getErrorCode()}.
 */
enum IonStoreError {
	/** Malformed request, invalid object id, or invalid pagination parameter; HTTP {@code 400}. */
	INVALID_REQUEST(10, "Invalid request"),
	/** Missing or invalid CWT bearer token; HTTP {@code 401}. The credentials need to be corrected. */
	UNAUTHORIZED(11, "Unauthorized"),
	/** The request is not permitted; HTTP {@code 403}. */
	FORBIDDEN(12, "Forbidden"),

	/** No object exists for the given reference id; HTTP {@code 404}. */
	OBJECT_NOT_FOUND(20, "Object not found"),
	/** The payload exceeds the service's configured maximum object size; HTTP {@code 413}. */
	OBJECT_TOO_LARGE(21, "Object size limit exceeded"),
	/** The requested {@code Ion-TTL} exceeds the service's configured maximum lifetime; HTTP {@code 403}. */
	TTL_EXCEEDED(22, "TTL limit exceeded"),
	/** The user's storage quota is exhausted; HTTP {@code 507}. Free space or retry later. */
	QUOTA_EXCEEDED(23, "Quota limit exceeded"),
	/**
	 * Request-rate limit exceeded; HTTP {@code 429}. Reserved for a future service capability; the
	 * current service does not yet report it, but the code is allocated so clients map it forward.
	 */
	RATE_LIMITED(24, "Rate limit exceeded"),
	/** The service detected an object-integrity failure on its side; HTTP {@code 422}. */
	INTEGRITY_ERROR(25, "Object integrity error"),

	/** The federation peer that should hold the object could not be located; HTTP {@code 502}. */
	PEER_NOT_FOUND(40, "Peer not found"),
	/** The service failed to issue the federated request to the peer; HTTP {@code 502}. */
	PEER_REQUEST_ERROR(41, "Peer request error"),
	/** The federation peer returned an error response (see the nested detail on the exception); HTTP {@code 502}. */
	PEER_RESPONSE_ERROR(42, "Peer response error"),

	/** The service encountered an I/O error while serving the request; HTTP {@code 500}. */
	IO_ERROR(50, "IO error"),
	/** The service's metadata store failed; HTTP {@code 500}. */
	METABASE_ERROR(51, "Metabase error"),
	/**
	 * A generic server-side failure, and the catch-all for an unexpected internal error with no more
	 * specific category; HTTP {@code 500}.
	 */
	SERVER_ERROR(99, "Ion Store server error"),

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