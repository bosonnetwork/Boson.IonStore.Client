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

import java.util.Objects;

import io.vertx.core.buffer.Buffer;

import io.bosonnetwork.Id;

/**
 * An {@link IonObject} that also carries its (integrity-verified) payload in memory.
 * <p>
 * Returned by the in-memory retrieval methods ({@link IonStore#getAsBytes(Id)} and
 * {@link IonStore#getAsBytes(Id, Id)}). Being an {@code IonObject}, it exposes all of the object's metadata
 * directly; {@link #getContent()} / {@link #getBytes()} additionally provide the bytes. This mirrors
 * the {@code put} side, which accepts bytes and returns an {@link IonObject}.
 * <p>
 * Equality and hashing are inherited from {@link IonObject} (i.e. based on metadata, not on the
 * payload bytes).
 */
public class BytesIonObject extends IonObject {
	private final Buffer content;

	/**
	 * Creates a {@code BytesIonObject} from object metadata and its payload.
	 *
	 * @param metadata the object metadata (must not be {@code null})
	 * @param content  the object payload (must not be {@code null})
	 */
	BytesIonObject(IonObject metadata, Buffer content) {
		super(metadata.getId(), metadata.getContentId(), metadata.getName(), metadata.getSize(),
				metadata.getContentType(), metadata.isEncrypted(), metadata.getExpireAt(),
				metadata.getMetadata(), metadata.getUri());
		this.content = Objects.requireNonNull(content, "content");
	}

	/**
	 * Returns the object payload as a {@link Buffer}.
	 *
	 * @return the payload buffer
	 */
	public Buffer getContent() {
		return content;
	}

	/**
	 * Returns the object payload as a newly allocated byte array.
	 *
	 * @return the payload bytes
	 */
	public byte[] getBytes() {
		return content.getBytes();
	}

	@Override
	public String toString() {
		return super.toString() + " (" + content.length() + " bytes)";
	}
}