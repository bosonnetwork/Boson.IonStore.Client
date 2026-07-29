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

public class RateLimitException extends IonStoreException {
	private static final long serialVersionUID = -8131044289523766712L;

	private final long retryAfter; // seconds

	/**
	 * Creates a {@code RateLimitException} from a service error response.
	 *
	 * @param status     the HTTP status code returned by the service
	 * @param message    the detail message
	 * @param nested     a description of the nested federation error, or {@code null}
	 * @param retryAfter the number of seconds to wait before retrying the request, or {@code 0} if absent
	 */
	public RateLimitException(int status, String message, String nested, long retryAfter) {
		super(status, IonStoreError.RATE_LIMITED.getCode(), message, nested);
		this.retryAfter = retryAfter;
	}

	/**
	 * Creates a {@code RateLimitException} from a service error response with no structured retry-after
	 *
	 * @param status  the HTTP status code returned by the service
	 * @param message the detail message
	 * @param nested  a description of the nested federation error, or {@code null}
	 */
	public RateLimitException(int status, String message, String nested) {
		this(status, message, nested, 0);
	}

	/**
	 * Retrieves the duration, in seconds, that the client should wait before retrying the request.
	 *
	 * @return the retry-after time in seconds, or {@code 0} if no retry-after value is provided.
	 */
	public long getRetryAfter() {
		return retryAfter;
	}
}
