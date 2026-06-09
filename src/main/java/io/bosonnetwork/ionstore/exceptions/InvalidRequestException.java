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
 * Thrown for a malformed request, an invalid object id, or an invalid pagination parameter; HTTP
 * {@code 400}. The request must be corrected before retrying.
 */
public class InvalidRequestException extends IonStoreException {
	private static final long serialVersionUID = 4186188836795245270L;

	/**
	 * Creates an {@code InvalidRequestException} from a service error response.
	 *
	 * @param status  the HTTP status code returned by the service
	 * @param message the detail message
	 * @param nested  a description of the nested federation error, or {@code null}
	 */
	public InvalidRequestException(int status, String message, String nested) {
		super(status, IonStoreError.INVALID_REQUEST.getCode(), message, nested);
	}
}