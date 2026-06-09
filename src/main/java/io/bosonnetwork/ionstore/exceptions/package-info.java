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
 * Exceptions thrown by the Ion Store client.
 * <p>
 * {@link io.bosonnetwork.ionstore.exceptions.IonStoreException} is the base type. Each error category
 * the service reports is mapped to a dedicated subclass, so callers can react by catching the specific
 * type instead of inspecting a status code:
 * <ul>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.UnauthorizedException} — HTTP {@code 401}</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.ForbiddenException} — HTTP {@code 403}</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.TtlExceededException} — HTTP {@code 403} (TTL cap)</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.InvalidRequestException} — HTTP {@code 400}</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.ObjectTooLargeException} — HTTP {@code 413}</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.QuotaExceededException} — HTTP {@code 429}</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.ObjectNotFoundException} — HTTP {@code 404}</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.ObjectIntegrityException} — content-id mismatch</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.IonStoreIOException},
 *       {@link io.bosonnetwork.ionstore.exceptions.IonStoreMetabaseException},
 *       {@link io.bosonnetwork.ionstore.exceptions.IonStoreServerException},
 *       {@link io.bosonnetwork.ionstore.exceptions.IonStoreInternalException} — server-side faults</li>
 *   <li>{@link io.bosonnetwork.ionstore.exceptions.PeerNotFoundException},
 *       {@link io.bosonnetwork.ionstore.exceptions.PeerRequestException},
 *       {@link io.bosonnetwork.ionstore.exceptions.PeerResponseException} — federation faults</li>
 * </ul>
 * Catching by type is preferable to branching on the HTTP status, since a single status can map to more
 * than one category (HTTP {@code 403} covers both {@code ForbiddenException} and
 * {@code TtlExceededException}). An error category the client does not recognize surfaces as a plain
 * {@code IonStoreException} that still preserves the original numeric error code.
 */
package io.bosonnetwork.ionstore.exceptions;
