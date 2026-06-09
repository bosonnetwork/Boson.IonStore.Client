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
 * Thrown when an object fails its integrity check: the SHA-256 of the bytes does not match the content
 * id the service advertised in the {@code Ion-Content-Id} header.
 * <p>
 * It is raised both for a <b>client-side</b> verification failure detected while a download is streamed
 * (a content-id mismatch, or a missing/malformed {@code Ion-Content-Id} header), in which case it
 * carries {@link #NO_HTTP_STATUS}; and for an <b>{@code INTEGRITY_ERROR}</b> reported by the service in
 * an error response, in which case it carries that response's HTTP status. Either way the underlying
 * service error code is {@code 11}.
 */
public class ObjectIntegrityException extends IonStoreException {
	private static final long serialVersionUID = 5894994639001863871L;

	/**
	 * Creates an integrity exception for a service-reported {@code INTEGRITY_ERROR} response.
	 *
	 * @param status  the HTTP status code returned by the service
	 * @param message the detail message
	 * @param nested  a description of the nested federation error, or {@code null}
	 */
	public ObjectIntegrityException(int status, String message, String nested) {
		super(status, IonStoreError.INTEGRITY_ERROR.getCode(), message, nested);
	}

	/**
	 * Creates an integrity exception for a client-side verification failure, with no HTTP status.
	 *
	 * @param message the detail message
	 */
	public ObjectIntegrityException(String message) {
		super(NO_HTTP_STATUS, IonStoreError.INTEGRITY_ERROR.getCode(), message, null);
	}
}