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
 * Thrown when a retrieval cannot deliver the plaintext the caller asked for: the request and the
 * stored object disagree about encryption, or the object cannot be framed for decryption.
 * <p>
 * This is a client-side condition, raised before any payload is delivered, so it always carries
 * {@link #NO_HTTP_STATUS} and {@link #NO_ERROR_CODE} - the service never reports it. It covers:
 * <ul>
 *   <li>an encrypted object retrieved without a decryption key (and without asking for the stored
 *       bytes as-is);</li>
 *   <li>a decryption key supplied for an object that is not encrypted;</li>
 *   <li>an encryption descriptor naming a scheme this client does not implement, or carrying a chunk
 *       size that is missing, malformed, or too small to hold an authentication tag.</li>
 * </ul>
 * <p>
 * It is deliberately distinct from {@code ObjectIntegrityException}: that one means the bytes are not
 * what the service committed to, whereas this one means the bytes were never going to be readable in
 * the form that was requested.
 */
public class DecryptionException extends IonStoreException {
	private static final long serialVersionUID = -2231548841556862290L;

	/**
	 * Creates a decryption exception with no HTTP status.
	 *
	 * @param message the detail message
	 */
	public DecryptionException(String message) {
		super(NO_HTTP_STATUS, message);
	}
}
