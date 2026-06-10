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
 * Thrown during a federated retrieval when the remote peer returns an error response.
 * <p>
 * The peer's own status and message are preserved both as the folded human-readable
 * {@link #getNested()} string (also appended to {@link #getMessage()}) and as the structured
 * {@link #getPeerStatus()} / {@link #getPeerMessage()} accessors, so callers can branch on the peer's
 * HTTP status directly.
 */
public class PeerResponseException extends IonStoreException {
	private static final long serialVersionUID = 7352025968333796396L;

	private final int peerStatus;
	private final String peerMessage;

	/**
	 * Creates a {@code PeerResponseException} from a service error response, with the structured peer
	 * detail extracted from the response's {@code nested} field.
	 *
	 * @param status      the HTTP status code returned by the service
	 * @param message     the detail message
	 * @param nested      a description of the nested peer error, or {@code null}
	 * @param peerStatus  the HTTP status the remote peer returned, or {@link #NO_HTTP_STATUS} if absent
	 * @param peerMessage the message the remote peer returned, or {@code null} if absent
	 */
	public PeerResponseException(int status, String message, String nested, int peerStatus, String peerMessage) {
		super(status, IonStoreError.PEER_RESPONSE_ERROR.getCode(), message, nested);
		this.peerStatus = peerStatus;
		this.peerMessage = peerMessage;
	}

	/**
	 * Creates a {@code PeerResponseException} from a service error response with no structured peer
	 * detail.
	 *
	 * @param status  the HTTP status code returned by the service
	 * @param message the detail message
	 * @param nested  a description of the nested peer error, or {@code null}
	 */
	public PeerResponseException(int status, String message, String nested) {
		this(status, message, nested, NO_HTTP_STATUS, null);
	}

	/**
	 * Returns the HTTP status the remote peer returned for the federated retrieval, or
	 * {@link #NO_HTTP_STATUS} ({@code 0}) when the service did not report one.
	 *
	 * @return the peer's HTTP status, or {@link #NO_HTTP_STATUS}
	 */
	public int getPeerStatus() {
		return peerStatus;
	}

	/**
	 * Returns the message the remote peer returned for the federated retrieval, or {@code null} when the
	 * service did not report one.
	 *
	 * @return the peer's message, or {@code null}
	 */
	public String getPeerMessage() {
		return peerMessage;
	}
}