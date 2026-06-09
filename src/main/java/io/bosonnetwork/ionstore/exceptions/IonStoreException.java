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

import java.nio.charset.StandardCharsets;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

import io.bosonnetwork.BosonException;

/**
 * Base type for every exception thrown by the Ion Store client.
 * <p>
 * Each error category the service reports is mapped to a dedicated subclass (for example
 * {@link UnauthorizedException}, {@link ObjectTooLargeException}, {@link QuotaExceededException},
 * {@link TtlExceededException}), so callers can react by catching the specific type:
 * <pre>{@code
 * try {
 *     store.put(bytes, options).get();
 * } catch (ExecutionException e) {
 *     if (e.getCause() instanceof QuotaExceededException qe)
 *         // free space or retry later
 *     else if (e.getCause() instanceof ObjectTooLargeException te)
 *         // reduce the payload size
 * }
 * }</pre>
 * Catching by type is preferable to branching on the HTTP {@linkplain #getStatus() status}, because a
 * single status can map to more than one category — HTTP {@code 403} is returned both for
 * {@link ForbiddenException} and for {@link TtlExceededException}.
 * <p>
 * When the failure corresponds to an HTTP error response, the exception preserves the useful details
 * of that response: the HTTP {@linkplain #getStatus() status code}, the service's stable
 * {@linkplain #getErrorCode() numeric error code}, a {@linkplain #getMessage() message}, and any
 * {@linkplain #getNested() nested federation detail}. When the failure is a transport- or client-side
 * error with no HTTP response (connection failure, TLS error, malformed response) the status is
 * {@link #NO_HTTP_STATUS} ({@code 0}), the code is {@link #NO_ERROR_CODE}, and the original error is
 * available via {@link #getCause()}.
 * <p>
 * An error category the client does not recognize (for example, one introduced by a newer service)
 * surfaces as a plain {@code IonStoreException} carrying the original numeric {@linkplain #getErrorCode()
 * code}.
 */
public class IonStoreException extends BosonException {
	private static final long serialVersionUID = -8740486856732079751L;

	/**
	 * Sentinel {@linkplain #getStatus() status} value indicating that the failure has no associated
	 * HTTP status code (i.e. a transport- or client-side error).
	 */
	public static final int NO_HTTP_STATUS = 0;

	/**
	 * Sentinel {@linkplain #getErrorCode() error code} value indicating that no service error code is
	 * associated with the failure (a transport-/client-side error, or an unrecognized category).
	 */
	public static final int NO_ERROR_CODE = -1;

	private final int status;
	private final int code;
	private final String nested;

	/**
	 * Creates an exception for an HTTP error response, fully classified.
	 *
	 * @param status  the HTTP status code returned by the service
	 * @param code    the stable numeric error code reported by the service, or {@link #NO_ERROR_CODE}
	 * @param message the detail message
	 * @param nested  a human-readable description of the nested federation error, or {@code null}
	 */
	public IonStoreException(int status, int code, String message, String nested) {
		super(message);
		this.status = status;
		this.code = code;
		this.nested = nested;
	}

	/**
	 * Creates an exception for an HTTP error response with no specific error code.
	 *
	 * @param status  the HTTP status code returned by the service
	 * @param message the detail message (typically the service error message or response body)
	 */
	public IonStoreException(int status, String message) {
		this(status, NO_ERROR_CODE, message, null);
	}

	/**
	 * Creates an exception for an HTTP error response, with an underlying cause.
	 *
	 * @param status  the HTTP status code returned by the service
	 * @param message the detail message
	 * @param cause   the underlying cause
	 */
	public IonStoreException(int status, String message, Throwable cause) {
		super(message, cause);
		this.status = status;
		this.code = NO_ERROR_CODE;
		this.nested = null;
	}

	/**
	 * Creates an exception for a transport- or client-side failure with no HTTP status (status is set
	 * to {@link #NO_HTTP_STATUS} and code to {@link #NO_ERROR_CODE}).
	 *
	 * @param message the detail message
	 * @param cause   the underlying cause
	 */
	public IonStoreException(String message, Throwable cause) {
		this(NO_HTTP_STATUS, message, cause);
	}

	/**
	 * Builds an exception from a service error response, mapping it to the most specific subclass.
	 * <p>
	 * The {@code Error} JSON payload is parsed for its {@code type}, {@code code} and {@code message}
	 * fields, plus any {@code nested} federation detail, to select the matching exception type and a
	 * developer-friendly message (with the nested peer detail appended, when present). The method
	 * falls back gracefully to the raw body, then to a status-derived message, when the body is empty
	 * or is not the expected JSON shape; an unrecognized category yields a plain
	 * {@code IonStoreException} that still preserves the original numeric code.
	 *
	 * @param status the HTTP status code of the response
	 * @param body   the (already read) response body, may be {@code null} or empty
	 * @return a classified {@code IonStoreException}, or a subclass thereof
	 */
	public static IonStoreException fromResponse(int status, Buffer body) {
		String type = null;
		int code = NO_ERROR_CODE;
		String message = null;
		String nested = null;

		if (body != null && body.length() > 0) {
			try {
				JsonObject json = new JsonObject(body);
				type = json.getString("type");
				code = json.getInteger("code", NO_ERROR_CODE);
				message = json.getString("message");
				nested = describeNested(json.getJsonObject("nested"));
			} catch (RuntimeException ignore) {
				// not the expected Error JSON; fall back to the raw body as the message below
			}
			if (message == null || message.isEmpty())
				message = body.toString(StandardCharsets.UTF_8);
		}

		IonStoreError error = IonStoreError.resolve(type, code);

		if (message == null || message.isEmpty())
			message = error != IonStoreError.UNKNOWN ? error.getDefaultMessage() : "HTTP " + status;
		// Fold the nested peer detail into the message so it remains visible in logs and stack traces;
		// it stays separately available through getNested().
		String displayMessage = nested == null ? message : message + " (" + nested + ")";

		return switch (error) {
			case UNAUTHORIZED -> new UnauthorizedException(status, displayMessage, nested);
			case FORBIDDEN -> new ForbiddenException(status, displayMessage, nested);
			case INVALID_REQUEST -> new InvalidRequestException(status, displayMessage, nested);
			case OBJECT_TOO_LARGE -> new ObjectTooLargeException(status, displayMessage, nested);
			case QUOTA_EXCEEDED -> new QuotaExceededException(status, displayMessage, nested);
			case TTL_EXCEEDED -> new TtlExceededException(status, displayMessage, nested);
			case OBJECT_NOT_FOUND -> new ObjectNotFoundException(status, displayMessage, nested);
			case IO_ERROR -> new IonStoreIOException(status, displayMessage, nested);
			case METABASE_ERROR -> new IonStoreMetabaseException(status, displayMessage, nested);
			case SERVER_ERROR -> new IonStoreServerException(status, displayMessage, nested);
			case INTEGRITY_ERROR -> new ObjectIntegrityException(status, displayMessage, nested);
			case PEER_NOT_FOUND -> new PeerNotFoundException(status, displayMessage, nested);
			case PEER_REQUEST_ERROR -> new PeerRequestException(status, displayMessage, nested);
			case PEER_RESPONSE_ERROR -> new PeerResponseException(status, displayMessage, nested);
			case INTERNAL_ERROR -> new IonStoreInternalException(status, displayMessage, nested);
			case UNKNOWN -> new IonStoreException(status, code, displayMessage, nested);
		};
	}

	// Renders the optional federation "nested" detail (peer status code and message) into a short,
	// human-readable suffix, or null when there is nothing useful to add.
	private static String describeNested(JsonObject nested) {
		if (nested == null)
			return null;

		Integer peerStatus = nested.getInteger("statusCode");
		String peerMessage = nested.getString("message");
		if (peerMessage == null || peerMessage.isEmpty()) {
			JsonObject peerError = nested.getJsonObject("error");
			if (peerError != null)
				peerMessage = peerError.getString("message");
		}

		if (peerStatus == null && (peerMessage == null || peerMessage.isEmpty()))
			return null;

		StringBuilder sb = new StringBuilder("peer responded");
		if (peerStatus != null)
			sb.append(" HTTP ").append(peerStatus);
		if (peerMessage != null && !peerMessage.isEmpty())
			sb.append(": ").append(peerMessage);
		return sb.toString();
	}

	/**
	 * Returns the HTTP status code associated with this failure, or {@link #NO_HTTP_STATUS}
	 * ({@code 0}) if the failure was a transport- or client-side error with no HTTP response.
	 *
	 * @return the HTTP status code, or {@link #NO_HTTP_STATUS} if none
	 */
	public int getStatus() {
		return status;
	}

	/**
	 * Returns the stable numeric error code reported by the service, or {@link #NO_ERROR_CODE} when the
	 * failure carries no service error code. The code is preserved even for an unrecognized category,
	 * which otherwise surfaces only as a plain {@code IonStoreException}.
	 *
	 * @return the numeric error code, or {@link #NO_ERROR_CODE}
	 */
	public int getErrorCode() {
		return code;
	}

	/**
	 * Returns a short, human-readable description of the nested federation error — the status and
	 * message the remote peer returned for a federated retrieval — or {@code null} when the failure did
	 * not originate from a peer. The same text is also appended to {@link #getMessage()}.
	 *
	 * @return the nested peer-error description, or {@code null} if there is none
	 */
	public String getNested() {
		return nested;
	}
}
