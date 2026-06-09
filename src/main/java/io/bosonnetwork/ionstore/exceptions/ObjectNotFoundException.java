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
 * Thrown when no object exists for the given reference id; HTTP {@code 404}.
 * <p>
 * Note that the Map-like retrieval and mutation methods do <em>not</em> throw this: {@code get} and
 * {@code getIonObject} return {@code null}, {@code exists} returns {@code false}, and {@code delete}
 * returns {@code false} when the object is absent. This exception surfaces only when the service
 * reports {@code OBJECT_NOT_FOUND} on a path where absence is not the expected outcome.
 */
public class ObjectNotFoundException extends IonStoreException {
	private static final long serialVersionUID = 2199229423689396054L;

	/**
	 * Creates an {@code ObjectNotFoundException} from a service error response.
	 *
	 * @param status  the HTTP status code returned by the service
	 * @param message the detail message
	 * @param nested  a description of the nested federation error, or {@code null}
	 */
	public ObjectNotFoundException(int status, String message, String nested) {
		super(status, IonStoreError.OBJECT_NOT_FOUND.getCode(), message, nested);
	}
}