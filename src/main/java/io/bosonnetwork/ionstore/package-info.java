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

/**
 * A client for the Boson Ion Store service &mdash; a content-addressed, deduplicated binary object
 * store with per-object metadata, TTL, per-user quota and cross-node federation.
 * <p>
 * The {@link io.bosonnetwork.ionstore.IonStore} client, constructed through its
 * {@linkplain io.bosonnetwork.ionstore.IonStore#builder() builder}, uploads, downloads, lists and
 * deletes objects over the service's HTTP API. Unlike a REST client built on Vert.x
 * {@code WebClient}, it uses the lower-level streaming {@link io.vertx.core.http.HttpClient} so that
 * arbitrary-size object payloads are transferred incrementally without being buffered whole in
 * memory.
 *
 * <h2>Integrity</h2>
 * Every payload download is verified: the client hashes the streamed bytes (SHA-256) and compares the
 * result against the content id the service advertises in the {@code Ion-Content-Id} header, failing
 * with {@link io.bosonnetwork.ionstore.exceptions.ObjectIntegrityException} on any mismatch.
 *
 * <h2>Authentication</h2>
 * Object retrieval is permissionless; upload, list and delete are authenticated with short-lived
 * {@link io.bosonnetwork.cwt.SignedCwt CWT} bearer tokens, minted in one of two mutually exclusive
 * modes: <b>user-key mode</b> (sign as the user) or <b>device mode</b> (sign as a device acting on
 * behalf of a user). Over HTTPS the service's self-signed certificate is pinned to its peer id.
 *
 * <h2>Errors</h2>
 * Failures are reported as {@link io.bosonnetwork.ionstore.exceptions.IonStoreException} or one of its
 * category-specific subclasses in {@link io.bosonnetwork.ionstore.exceptions} (for example
 * {@link io.bosonnetwork.ionstore.exceptions.QuotaExceededException} or
 * {@link io.bosonnetwork.ionstore.exceptions.TtlExceededException}), so callers can react by catching
 * the specific type. Each exception preserves the HTTP status, the service's numeric error code, and a
 * message; transport- or client-side failures (including integrity errors) carry
 * {@link io.bosonnetwork.ionstore.exceptions.IonStoreException#NO_HTTP_STATUS}.
 *
 * @see io.bosonnetwork.ionstore.IonStore
 * @see io.bosonnetwork.ionstore.IonObject
 * @see io.bosonnetwork.ionstore.exceptions.IonStoreException
 */
package io.bosonnetwork.ionstore;