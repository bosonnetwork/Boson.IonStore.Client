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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntFunction;
import java.util.function.Supplier;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.AsyncFile;
import io.vertx.core.file.OpenOptions;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.http.PoolOptions;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.TrustOptions;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.WriteStream;
import org.jspecify.annotations.NullUnmarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bosonnetwork.Id;
import io.bosonnetwork.Identity;
import io.bosonnetwork.crypto.CryptoIdentity;
import io.bosonnetwork.crypto.Hash;
import io.bosonnetwork.crypto.HybridTrustManager;
import io.bosonnetwork.crypto.SecretStream;
import io.bosonnetwork.crypto.Signature;
import io.bosonnetwork.cwt.SignedCwt;
import io.bosonnetwork.ionstore.exceptions.DecryptionException;
import io.bosonnetwork.ionstore.exceptions.IonStoreException;
import io.bosonnetwork.ionstore.exceptions.ObjectIntegrityException;
import io.bosonnetwork.service.AccessScope;
import io.bosonnetwork.utils.Base58;
import io.bosonnetwork.utils.Hex;
import io.bosonnetwork.vertx.AsyncInputStream;
import io.bosonnetwork.vertx.AsyncOutputStream;
import io.bosonnetwork.vertx.BufferReadStream;
import io.bosonnetwork.vertx.BufferWriteStream;
import io.bosonnetwork.vertx.ByteArrayReadStream;
import io.bosonnetwork.vertx.ContextualFuture;
import io.bosonnetwork.vertx.ObservableReadStream;
import io.bosonnetwork.web.PaginatedResult;

/**
 * A streaming client for a Boson Ion Store service: a content-addressed, deduplicated binary object
 * store.
 * <p>
 * The client uploads, downloads, lists, and deletes objects over the service's HTTP API. It is built
 * on the lower-level Vert.x {@link HttpClient} rather than the {@code WebClient} so that
 * arbitrary-size payloads are streamed incrementally instead of being buffered whole in memory.
 *
 * <h2>Integrity</h2>
 * Payload downloads are integrity-checked: the streamed bytes are hashed (SHA-256) and compared
 * against the content id the service advertises in the {@code Ion-Content-Id} header. A mismatch (or
 * a missing/malformed header) fails the download with {@link ObjectIntegrityException}. Because the
 * content id covers the whole object, ranged downloads are intentionally not offered - a partial body
 * cannot be verified.
 *
 * <h2>Encryption</h2>
 * A put may be encrypted client-side by supplying a key to {@link PutRequest#encrypt(byte[])}. The
 * service only ever sees ciphertext: the payload is encrypted as it streams, and the key never leaves
 * the client. Objects encrypted this way carry an {@code Ion-Encrypted} flag and an
 * {@code Ion-Encryption} descriptor naming the scheme and chunk size, so a reader can frame the
 * stream correctly without knowing what the writer's defaults were.
 *
 * <p><b>Encryption defeats deduplication, by design.</b> The store is content-addressed: an object's
 * content id is the SHA-256 of the bytes the service received, and identical bytes collapse to one
 * stored object. Encryption is randomised - every stream begins with a fresh random header - so the
 * same plaintext encrypts to different ciphertext on every put, yielding a different content id each
 * time. Two consequences follow:
 * <ul>
 *   <li>Uploading identical plaintext twice stores it twice; the service cannot tell the two apart,
 *       and neither copy is charged against the other's quota.</li>
 *   <li>A retried put is a <em>new</em> object, not a re-put of the previous one. Callers that retry
 *       must treat the returned id as authoritative and discard the earlier one.</li>
 * </ul>
 * This is the intended trade-off: dropping it would require deterministic encryption, which would
 * leak plaintext equality to the service. Callers that need dedup across identical plaintexts should
 * store those objects unencrypted.
 *
 * <p>Ciphertext is slightly larger than its plaintext - a one-off stream header plus a per-chunk
 * authentication tag. {@link EncryptedReadStream#getCipherTextSize(long, int)} gives the exact
 * expansion, and {@link DecryptedWriteStream#getPlainTextSize(long, int)} inverts it, so the size
 * reported by the service can be mapped back to the plaintext size a caller cares about.
 *
 * <h2>Authentication</h2>
 * Object retrieval is permissionless and sends no token. Upload, list, and delete carry a short-lived
 * {@link SignedCwt CWT} bearer token, signed by the device key ({@link Builder#deviceKey}) on behalf
 * of a user. The user is identified either by its key pair ({@link Builder#userKey}, which derives the
 * user id) or by its id directly ({@link Builder#userId}); a device key is required either way. Over
 * HTTPS the service's self-signed certificate is pinned to its peer id.
 *
 * <h2>Connection reuse</h2>
 * Connections are pooled and reused, but are held for reuse only briefly: a connection that has gone
 * idle can be closed by the peer, the network, or - on mobile - the host platform, and nothing detects
 * that until a request is written into it and the write fails. Expiring pooled connections well inside
 * that window keeps the common case a fresh connection rather than a dead one.
 * <p>
 * <b>No request is ever retried automatically.</b> A transport failure tells us only that no response
 * arrived - never whether the service received and acted on the request - so retrying is a judgement
 * the caller is better placed to make: it knows whether repeating the operation is acceptable, and its
 * retry is visible where a silent one would not be. This applies uniformly, to reads and writes alike.
 *
 * <h2>Lifecycle &amp; threading</h2>
 * The underlying {@link HttpClient} is created when the client is constructed, so a client is ready
 * to use as soon as it is built; call {@link #close()} when finished to release it. Requests issued
 * after {@link #close()} fail with {@link IllegalStateException}. The returned
 * {@link ContextualFuture}s complete on the caller's Vert.x context.
 *
 * <p>Instances are obtained through {@link #builder()}.
 */
public class IonStore {
	private static final long ACCESS_TOKEN_TIMEOUT = 10 * 60 * 1000;

	// current supported API version prefix
	private static final String API_VERSION_PREFIX = "/v1";

	protected static final int CHUNK_SIZE = 32 * 1024;
	protected static final int CHUNK_SIZE_FOR_ENCRYPTION = CHUNK_SIZE - SecretStream.ABYTES;

	// Size threshold for the byte[] put: arrays smaller than this are copied into a single buffer and
	// sent in one shot; larger arrays are streamed from the array (see put(byte[], PutOptions)).
	private static final int IN_MEMORY_PUT_THRESHOLD = 1024 * 1024; // 1 MiB

	// Seconds an idle connection may be reused from the pool. See the HttpClientOptions setup.
	private static final int KEEP_ALIVE_TIMEOUT = 20;

	// Ion-* header names (mirrors the service's IonStoreHeaders; redeclared here to avoid depending
	// on the service module).
	private static final String ION_HEADER_PREFIX = "Ion-";
	private static final String ION_TTL = "Ion-TTL";
	private static final String ION_ENCRYPTED = "Ion-Encrypted";
	private static final String ION_EXPIRE_AT = "Ion-Expire-At";
	private static final String ION_CONTENT_ID = "Ion-Content-Id";

	/**
	 * Describes how a client-encrypted payload is framed, so a reader can decrypt it without having
	 * to assume the writer used today's defaults. Emitted on every encrypted put and echoed by the
	 * service on get.
	 * <p>
	 * Deliberately <em>not</em> reserved server-side: the service stores and returns it as ordinary
	 * {@code Ion-*} object metadata and never interprets it, so the format can evolve without a
	 * service change. The client sets it itself and ignores any caller-supplied value.
	 *
	 * @see #ION_ENCRYPTION_SECRETSTREAM
	 */
	// Package-private: IonObject reads the descriptor off its own metadata to report the plaintext size.
	static final String ION_ENCRYPTION = "Ion-Encryption";

	// Value of the Ion-Encryption header: "<scheme>; chunk=<encrypted chunk size>". The scheme names
	// the AEAD construction; chunk is the size of a full *encrypted* block (plain chunk + auth tag),
	// which is the value the decrypting side feeds straight into DecryptedWriteStream - no unit
	// conversion at the point of use. Readers must tolerate unknown parameters and extra whitespace.
	private static final String ION_ENCRYPTION_SECRETSTREAM = "secretstream/xchacha20poly1305";

	// The chunk parameter of the Ion-Encryption value, with its separator, as it is written and matched.
	private static final String ION_ENCRYPTION_CHUNK = "chunk=";

	private final Vertx vertx;

	private final Id userId;
	private final Identity deviceIdentity;

	private final Id servicePeerId;
	private final URL serviceUrl;

	private final String host;
	private final int port;
	// Service URL path (sans trailing slash) plus the API version prefix; all request URIs append to it.
	private final String basePath;

	private final HttpClient httpClient;
	private volatile @Nullable AccessTokenCache tokenCache;

	private volatile boolean closed;

	private static final Logger log = LoggerFactory.getLogger(IonStore.class);

	private record AccessTokenCache(String token, long createdAt) {}

	private IonStore(Builder builder) {
		this.vertx = Objects.requireNonNull(builder.vertx, "Vert.x instance must be set");
		this.userId = Objects.requireNonNull(builder.userId, "Either userId or userKey must be set");

		Objects.requireNonNull(builder.deviceKey, "deviceKey must be set");
		this.deviceIdentity = new CryptoIdentity(builder.deviceKey);

		this.servicePeerId = Objects.requireNonNull(builder.servicePeerId, "servicePeerId must be set");
		this.serviceUrl = Objects.requireNonNull(builder.serviceUrl, "serviceUrl must be set");

		boolean ssl = serviceUrl.getProtocol().equals("https");
		this.host = serviceUrl.getHost();
		this.port = serviceUrl.getPort() > 0 ? serviceUrl.getPort() : serviceUrl.getDefaultPort();

		String path = serviceUrl.getPath().replaceAll("/+$", "");
		this.basePath = path + API_VERSION_PREFIX;

		PoolOptions poolOptions = new PoolOptions()
				.setHttp1MaxSize(16)
				.setMaxWaitQueueSize(1_000);

		HttpClientOptions options = new HttpClientOptions()
				.setSsl(ssl)
				.setDefaultHost(host)
				.setDefaultPort(port)
				.setKeepAlive(true)
				// How long an idle connection may be kept in the pool for reuse. Deliberately short:
				// mobile platforms and NAT gateways silently kill idle sockets after a period of
				// inactivity, and a pooled connection that died that way is indistinguishable from a
				// live one until a request is written into it and fails. Expiring the pool well inside
				// that window means the common case is a fresh connection rather than a dead one.
				// Expiry is wall-clock, so a connection that sat through a device sleep is already
				// stale on wake and is evicted rather than handed out.
				.setKeepAliveTimeout(KEEP_ALIVE_TIMEOUT)
				.setPipelining(false)            // safer for large streaming responses
				.setMaxChunkSize(16 * 1024)      // 16 KB chunks (balanced default)
				.setDecompressionSupported(false) // avoid buffering for transparent decompression
				.setConnectTimeout(10_000)
				.setIdleTimeout(60)
				.setIdleTimeoutUnit(TimeUnit.SECONDS)
				.setProtocolVersion(HttpVersion.HTTP_1_1);

		if (ssl)
			options.setEnabledSecureTransportProtocols(Set.of("TLSv1.2", "TLSv1.3"))
					.setTrustOptions(TrustOptions.wrap(
							new HybridTrustManager(servicePeerId.toString(), servicePeerId.bytesUnsafe())));

		httpClient = vertx.createHttpClient(options, poolOptions);
		closed = false;
	}

	/**
	 * Returns the user id this client acts as: the id derived from the user key in user-key mode, or
	 * the configured user id in device mode.
	 *
	 * @return the user id
	 */
	public Id getUserId() {
		return userId;
	}

	/**
	 * Returns the device id this client signs tokens with.
	 *
	 * @return the device id
	 */
	public Id getDeviceId() {
		return deviceIdentity.getId();
	}

	/**
	 * Returns the peer id of the bound Ion Store service.
	 *
	 * @return the service peer id
	 */
	public Id getServicePeerId() {
		return servicePeerId;
	}

	/**
	 * Returns the base URL of the bound Ion Store service.
	 *
	 * @return the service URL
	 */
	public URL getServiceUrl() {
		return serviceUrl;
	}

	/**
	 * Close the client and the underlying {@link HttpClient}.
	 *
	 * @return a future completing when the client is closed
	 */
	public ContextualFuture<Void> close() {
		if (closed)
			return ContextualFuture.succeededFuture();

		closed = true;
		return ContextualFuture.of(httpClient.close());
	}


	public boolean isClosed() {
		return closed;
	}

	private void closedCheck() {
		if (closed)
			throw new IllegalStateException("Client is closed");
	}

	// Runs the transfer on a Vert.x context rather than on the caller's thread. The in-memory
	// destination is backed by BufferWriteStream, which binds to the current context at construction
	// and refuses to be built off one; arranging that here means a caller on an ordinary thread behaves
	// the same as one already on a context, which is what put() does too.
	private <T> Future<T> onContext(Supplier<Future<T>> action) {
		Promise<T> promise = Promise.promise();
		vertx.getOrCreateContext().runOnContext(v -> {
			try {
				action.get().onComplete(promise);
			} catch (Throwable t) {
				promise.fail(t);
			}
		});

		return promise.future();
	}

	public PutRequest put() {
		return new PutRequest(this);
	}

	private Future<IonObject> upload(Buffer content, PutRequest options) {
		// Client-side upload integrity: hash exactly the bytes we send and verify the server committed to
		// the same content id (see verifyUploadedContentId), so a corrupted/partial upload fails here.
		MessageDigest md = Hash.sha256();
		md.update(content.getBytes());
		Id expectedContentId = Id.of(md.digest());

		return httpClient.request(requestOptions(HttpMethod.POST, uri("/objects")))
				.compose(request -> {
					applyUploadHeaders(request, options);
					return request.send(content);
				})
				.compose(this::handleUploadResponse)
				.compose(obj -> verifyUploadedContentId(obj, expectedContentId))
				.recover(IonStore::wrapError);
	}

	private Future<IonObject> upload(ReadStream<Buffer> stream, PutRequest options) {
		// Hash the bytes as they stream out and verify the server committed to the same content id, so a
		// silently corrupted or truncated upload fails here instead of being stored (and later served) as
		// a valid-looking but broken object. Symmetric to the download-side integrity check.
		MessageDigest md = Hash.sha256();
		ReadStream<Buffer> observed = new ObservableReadStream<>(stream, buf -> md.update(buf.getBytes()));
		return httpClient.request(requestOptions(HttpMethod.POST, uri("/objects")))
				.compose(request -> {
					applyUploadHeaders(request, options);
					return request.send(observed);
				})
				.compose(this::handleUploadResponse)
				.compose(obj -> verifyUploadedContentId(obj, Id.of(md.digest())))
				.recover(IonStore::wrapError);
	}

	Future<IonObject> put(PutRequest request) {
		closedCheck();
		// Snapshot up front so mutating the request afterwards cannot disturb an upload in flight,
		// and so the resolution below is free to fill in derived values (length, probed type, name).
		PutRequest options = request.dup();
		return onContext(() -> resolveAndUpload(options));
	}

	// Turns the request's content source into bytes-on-the-wire. Every source funnels into upload(),
	// which is the single place encryption and the declared content length are applied - so the two
	// stay in step no matter where the payload came from.
	private Future<IonObject> resolveAndUpload(PutRequest options) {
		return switch (options.contentSource()) {
			case EMPTY -> Future.failedFuture(new IllegalStateException("Empty content"));

			case BYTES -> {
				byte[] bytes = options.content();
				yield uploadInMemory(bytes.length, options, () -> Buffer.buffer(bytes),
						chunkSize -> new ByteArrayReadStream(bytes, 0, bytes.length, chunkSize));
			}

			case BUFFER -> {
				Buffer buf = options.content();
				yield uploadInMemory(buf.length(), options, () -> buf,
						chunkSize -> new BufferReadStream(buf, 0, buf.length(), chunkSize));
			}

			case FILE -> {
				Path file = options.content();
				long length;
				try {
					length = Files.size(file);
					// A file names and types itself, unless the caller said otherwise.
					if (options.contentType() == null) {
						String contentType = Files.probeContentType(file);
						if (contentType != null)
							options.contentType(contentType);
					}
					if (options.name() == null)
						options.name(file.getFileName().toString());
				} catch (IOException e) {
					yield Future.failedFuture(new IonStoreException("Cannot read file: " + file, e));
				}

				yield vertx.fileSystem()
						.open(file.toString(), new OpenOptions().setRead(true).setWrite(false))
						.compose(af -> {
							af.setReadBufferSize(sourceChunkSize(options));
							// Close the source file once the upload settles, then propagate its original outcome.
							return uploadStream(af, length, options).transform(ar -> af.close().transform(x ->
									ar.succeeded() ? Future.succeededFuture(ar.result()) :
											Future.failedFuture(ar.cause())));
						});
			}

			case INPUT_STREAM -> uploadStream(
					new AsyncInputStream(options.content(), sourceChunkSize(options), options.closeContent()),
					options.contentLength(), options);

			case READ_STREAM -> uploadStream(options.content(), options.contentLength(), options);
		};
	}

	// An in-memory payload is already whole in the caller's heap, so streaming it does not reduce the
	// footprint - it only avoids the single copy Buffer.buffer makes, at the cost of per-chunk context
	// hops. That trade-off only pays off for large payloads, so send small ones in one shot and stream
	// the rest. Encryption always streams, whatever the size.
	private Future<IonObject> uploadInMemory(long length, PutRequest options, Supplier<Buffer> whole,
			IntFunction<ReadStream<Buffer>> streamed) {
		if (options.encryptionKey() == null && length < IN_MEMORY_PUT_THRESHOLD) {
			options.contentLength(length);
			return upload(whole.get(), options);
		}

		return uploadStream(streamed.apply(sourceChunkSize(options)), length, options);
	}

	// The one place encryption is applied. Wrapping here (rather than per content source) keeps the
	// declared content length in step with the bytes that actually go out: an encrypted body is longer
	// than its plaintext by a stream header plus a per-chunk auth tag.
	private Future<IonObject> uploadStream(ReadStream<Buffer> source, long plainLength, PutRequest options) {
		byte[] key = options.encryptionKey();
		if (key == null) {
			options.contentLength(plainLength);
			return upload(source, options);
		}

		// A length of 0 means "unknown", and stays unknown once encrypted - the upload goes out chunked.
		options.contentLength(plainLength > 0 ?
				EncryptedReadStream.getCipherTextSize(plainLength, CHUNK_SIZE_FOR_ENCRYPTION) : 0);
		return upload(new EncryptedReadStream(source, key, CHUNK_SIZE_FOR_ENCRYPTION, null), options);
	}

	// Read buffer for a payload source: sized so that one plain chunk encrypts to exactly CHUNK_SIZE.
	private static int sourceChunkSize(PutRequest options) {
		return options.encryptionKey() == null ? CHUNK_SIZE : CHUNK_SIZE_FOR_ENCRYPTION;
	}

	private void applyUploadHeaders(HttpClientRequest request, PutRequest options) {
		request.putHeader("Authorization", "Bearer " + getAccessToken());
		request.putHeader("Content-Type", options.contentType() != null ?
				options.contentType() : "application/octet-stream");
		String name = options.name();
		if (name != null)
			request.putHeader("Content-Disposition", contentDisposition(name));
		if (options.ttl() > 0)
			request.putHeader(ION_TTL, Long.toString(options.ttl()));
		if (options.isEncrypted()) {
			request.putHeader(ION_ENCRYPTED, "true");
			// Record how the ciphertext is framed so a future reader is not pinned to whatever the
			// chunk size happened to be at upload time. CHUNK_SIZE is the encrypted block size; the
			// plain chunk fed to EncryptedReadStream is that minus the per-block tag.
			request.putHeader(ION_ENCRYPTION, encryptionDescriptor(CHUNK_SIZE));
		}
		options.metadata().forEach((k, v) -> {
			String key = k.regionMatches(true, 0, ION_HEADER_PREFIX, 0, ION_HEADER_PREFIX.length()) ?
					k : ION_HEADER_PREFIX + k;
			// never let custom metadata override a header the client sets itself
			if (!isManagedOnPut(key))
				request.putHeader(key, String.valueOf(v));
		});

		if (options.contentLength() > 0)
			request.putHeader("Content-Length", Long.toString(options.contentLength()));
		else
			request.setChunked(true);
	}

	private Future<IonObject> handleUploadResponse(HttpClientResponse response) {
		if (response.statusCode() == 201) {
			return response.body().compose(buf -> {
				try {
					return Future.succeededFuture(IonObject.fromJson(new JsonObject(buf)));
				} catch (Exception e) {
					return Future.failedFuture(new IonStoreException("Malformed upload response", e));
				}
			});
		}

		return failFromResponse(response);
	}

	// Fails the upload if the object the server stored does not carry the content id computed over the
	// bytes we actually sent (a partial or corrupted upload). The orphaned server object, if any, is
	// left to expire by its TTL.
	private Future<IonObject> verifyUploadedContentId(IonObject obj, Id expectedContentId) {
		if (!expectedContentId.equals(obj.getContentId()))
			return Future.failedFuture(new ObjectIntegrityException(
					"Upload integrity check failed for object " + obj.getId() + ": expected content id " +
							expectedContentId + ", server stored " + obj.getContentId()));
		return Future.succeededFuture(obj);
	}

	/**
	 * Starts a retrieval of an object held by the bound service.
	 * <p>
	 * The returned {@link GetRequest} is configured and then dispatched by naming a destination; see
	 * {@link GetRequest} for the shape of the API and for what each destination returns.
	 *
	 * @param id the object reference id (must not be {@code null})
	 * @return a retrieval request to configure and dispatch
	 */
	public GetRequest get(Id id) {
		Objects.requireNonNull(id, "id");
		return new GetRequest(this, null, id);
	}

	/**
	 * Starts a retrieval of a federated object: one held by a remote peer, which the bound service
	 * fetches and caches on demand (see {@link #get(Id)}).
	 *
	 * @param peerId the peer id of the Ion Store node holding the object (must not be {@code null})
	 * @param id     the object reference id (must not be {@code null})
	 * @return a retrieval request to configure and dispatch
	 */
	public GetRequest get(Id peerId, Id id) {
		Objects.requireNonNull(peerId, "peerId");
		Objects.requireNonNull(id, "id");
		return new GetRequest(this, peerId, id);
	}

	// The entry points behind GetRequest's destinations. Each one owns the setup its destination needs
	// and then hands off to the single download() below, which is where the wire protocol - integrity
	// check included - lives.

	Future<Optional<BytesIonObject>> getToBytes(@Nullable Id peerId, Id id, byte @Nullable [] key, boolean raw) {
		closedCheck();
		return onContext(() -> {
			BufferWriteStream ws = new BufferWriteStream();
			return download(peerId, id, key, raw, ws).compose(meta -> meta.isEmpty() ?
					Future.succeededFuture(Optional.<BytesIonObject>empty()) :
					ws.getBuffer().map(buf -> meta.map(o -> new BytesIonObject(o, buf))));
		}).recover(IonStore::wrapError);
	}

	Future<Optional<IonObject>> getToBuffer(@Nullable Id peerId, Id id, byte @Nullable [] key, boolean raw,
			Buffer buffer) {
		closedCheck();
		return onContext(() -> download(peerId, id, key, raw, new BufferWriteStream(buffer)))
				.recover(IonStore::wrapError);
	}

	Future<Optional<IonObject>> getToFile(@Nullable Id peerId, Id id, byte @Nullable [] key, boolean raw,
			Path file) {
		closedCheck();
		return onContext(() -> {
			String path = file.toString();
			return vertx.fileSystem()
					.open(path, new OpenOptions().setWrite(true).setCreate(true).setTruncateExisting(true))
					// A file that was created for an object that turns out to be missing, or that holds a
					// partial or corrupt payload, is worse than no file at all - roll it back either way.
					.compose(af -> download(peerId, id, key, raw, af)
							.recover(e -> closeAndDelete(af, path).transform(x -> Future.failedFuture(e)))
							.compose(meta -> meta.isPresent() ?
									Future.succeededFuture(meta) :
									closeAndDelete(af, path).map(meta)));
		}).recover(IonStore::wrapError);
	}

	Future<Optional<IonObject>> getToOutputStream(@Nullable Id peerId, Id id, byte @Nullable [] key, boolean raw,
			OutputStream stream, boolean closeStream) {
		closedCheck();
		return onContext(() -> {
			AsyncOutputStream out = new AsyncOutputStream(stream, closeStream);
			// pipeTo() ends the destination only when a transfer actually ran: a miss, or a failure
			// raised from the response headers, leaves it untouched - and a stream this client was asked
			// to close still has to be closed. end() is idempotent, so this is a no-op after a completed
			// transfer, and the original outcome is propagated either way.
			return download(peerId, id, key, raw, out).transform(ar -> out.end().transform(x ->
					ar.succeeded() ? Future.succeededFuture(ar.result()) : Future.failedFuture(ar.cause())));
		}).recover(IonStore::wrapError);
	}

	// The one destination this client does not own: a caller's WriteStream is left exactly as pipeTo()
	// left it - ended on a completed transfer, untouched otherwise - so the caller keeps the choice.
	Future<Optional<IonObject>> getToWriteStream(@Nullable Id peerId, Id id, byte @Nullable [] key, boolean raw,
			WriteStream<Buffer> stream) {
		closedCheck();
		return onContext(() -> download(peerId, id, key, raw, stream)).recover(IonStore::wrapError);
	}

	// Streams the payload to dst, decrypting on the way when a key is given. On HTTP 200 the content is
	// hashed while it pipes and checked against the advertised Ion-Content-Id; the hash covers the bytes
	// as they arrive, which for an encrypted object is the ciphertext - exactly what the put side
	// committed to. On 404 the body is drained and an empty result is returned.
	private Future<Optional<IonObject>> download(@Nullable Id peerId, Id id, byte @Nullable [] key, boolean raw,
			WriteStream<Buffer> dst) {
		Id ownerPeerId = peerId == null ? servicePeerId : peerId;
		String uri = peerId == null ? uri("/objects/" + id) : uri("/objects/" + peerId + "/" + id);

		return httpClient.request(requestOptions(HttpMethod.GET, uri))
				.compose(HttpClientRequest::send)
				.compose(response -> {
					int statusCode = response.statusCode();
					if (statusCode == 404)
						return Future.succeededFuture(Optional.empty());
					if (statusCode != 200)
						return failFromResponse(response);

					String cid = response.headers().get(ION_CONTENT_ID);
					if (cid == null)
						return drainAndFail(response, new ObjectIntegrityException("Missing Ion-Content-Id header"));
					Id expectedContentId;
					try {
						expectedContentId = Id.of(cid);
					} catch (IllegalArgumentException e) {
						return drainAndFail(response, new ObjectIntegrityException("Malformed Ion-Content-Id header: " + cid));
					}

					boolean encrypted = Boolean.parseBoolean(response.headers().get(ION_ENCRYPTED));

					// The request and the object have to agree about encryption. Silently ignoring a
					// mismatch either way hands the caller bytes that are not what they asked for: the
					// unreadable ciphertext of an object they have no key for, or plaintext from a get
					// they wrote as though it were confidential. raw() is how a caller opts out of the
					// whole question and takes the stored bytes as they are.
					WriteStream<Buffer> target = dst;
					if (!raw) {
						if (encrypted) {
							if (key == null)
								return drainAndFail(response, new DecryptionException(
										"Object " + id + " is encrypted; supply its key with decrypt(), or ask " +
												"for the stored bytes with raw()"));

							int chunkSize;
							try {
								chunkSize = parseEncryptionDescriptor(response.headers().get(ION_ENCRYPTION));
							} catch (DecryptionException e) {
								return drainAndFail(response, e);
							}

							target = new DecryptedWriteStream(dst, key, chunkSize, null);
						} else if (key != null) {
							return drainAndFail(response, new DecryptionException(
									"Object " + id + " is not encrypted, but a decryption key was supplied"));
						}
					}

					MessageDigest md = Hash.sha256();
					AtomicLong size = new AtomicLong();
					ReadStream<Buffer> observed = new ObservableReadStream<>(response, buf -> {
						md.update(buf.getBytes());
						size.addAndGet(buf.length());
					});

					return observed.pipeTo(target).compose(v -> {
						Id actualContentId = Id.of(md.digest());
						if (!actualContentId.equals(expectedContentId))
							return Future.failedFuture(new ObjectIntegrityException(
									"Integrity check failed for object " + id + ": expected content id " +
											expectedContentId + ", computed " + actualContentId));
						return Future.succeededFuture(Optional.of(ionObjectFromHeaders(ownerPeerId, id, response, size.get())));
					});
				});
	}

	private IonObject ionObjectFromHeaders(Id ownerPeerId, Id id, HttpClientResponse response, long size) {
		String cid = Objects.requireNonNull(response.headers().get(ION_CONTENT_ID),
				"Response is missing the " + ION_CONTENT_ID + " header");
		Id contentId = Id.of(cid);
		String name = getFileName(response.headers().get("Content-Disposition"));
		String contentType = response.headers().get("Content-Type");
		boolean encrypted = Boolean.parseBoolean(response.headers().get(ION_ENCRYPTED));

		long expireAt;
		try {
			String v = response.headers().get(ION_EXPIRE_AT);
			expireAt = v == null ? 0 : Long.parseLong(v);
		} catch (NumberFormatException e) {
			expireAt = 0;
		}

		Map<String, Object> metadata = new HashMap<>();
		response.headers().forEach(e -> {
			if (e.getKey().regionMatches(true, 0, ION_HEADER_PREFIX, 0, ION_HEADER_PREFIX.length()) && !isReserved(e.getKey()))
				metadata.put(e.getKey(), e.getValue());
		});

		String uri = "ions://" + ownerPeerId + "/" + id;
		return new IonObject(id, contentId, name, size, contentType, encrypted, expireAt, metadata, uri);
	}

	/**
	 * Retrieves an object's metadata without downloading its payload.
	 *
	 * @param id the object reference id (must not be {@code null})
	 * @return a future completing with the metadata, or {@code null} if the object was not found
	 */
	public ContextualFuture<Optional<IonObject>> getIonObject(Id id) {
		Objects.requireNonNull(id, "id");
		closedCheck();

		Future<Optional<IonObject>> future = httpClient.request(requestOptions(HttpMethod.GET, uri("/objects/" + id)))
				.compose(request -> {
					request.putHeader("Accept", "application/json");
					return request.send();
				})
				.compose(response -> {
					if (response.statusCode() == 200) {
						return response.body().compose(buf -> {
							try {
								return Future.succeededFuture(Optional.of(IonObject.fromJson(new JsonObject(buf))));
							} catch (Exception e) {
								return Future.failedFuture(new IonStoreException("Malformed metadata response", e));
							}
						});
					} else if (response.statusCode() == 404) {
						return Future.succeededFuture(Optional.<IonObject>empty());
					} else {
						return failFromResponse(response);
					}
				})
				.recover(IonStore::wrapError);

		return ContextualFuture.of(future);
	}

	/**
	 * Tests whether an object exists.
	 *
	 * @param id the object reference id (must not be {@code null})
	 * @return a future completing with {@code true} if the object exists, {@code false} otherwise
	 */
	public ContextualFuture<Boolean> exists(Id id) {
		Objects.requireNonNull(id, "id");
		closedCheck();

		Future<Boolean> future = httpClient.request(requestOptions(HttpMethod.HEAD, uri("/objects/" + id)))
				.compose(HttpClientRequest::send)
				.compose(response -> {
					if (response.statusCode() == 200)
						return Future.succeededFuture(true);
					else if (response.statusCode() == 404)
						return Future.succeededFuture(false);
					else
						return failFromResponse(response);
				})
				.recover(IonStore::wrapError);

		return ContextualFuture.of(future);
	}

	/**
	 * Lists the objects owned by the authenticated user, newest first.
	 *
	 * @param page     the 1-based page index (must be {@code >= 1})
	 * @param pageSize the number of items per page (must be {@code >= 1}; clamped server-side)
	 * @return a future completing with a page of object metadata
	 */
	public ContextualFuture<PaginatedResult<IonObject>> list(long page, long pageSize) {
		if (page < 1)
			throw new IllegalArgumentException("page must be >= 1");
		if (pageSize < 1)
			throw new IllegalArgumentException("pageSize must be >= 1");
		closedCheck();

		String uri = uri("/objects") + "?page=" + page + "&pageSize=" + pageSize;
		Future<PaginatedResult<IonObject>> future = httpClient.request(requestOptions(HttpMethod.GET, uri))
				.compose(request -> {
					request.putHeader("Authorization", "Bearer " + getAccessToken());
					return request.send();
				})
				.compose(response -> {
					if (response.statusCode() == 200) {
						return response.body().compose(buf -> {
							try {
								JsonObject body = new JsonObject(buf);
								JsonArray items = body.getJsonArray("items");
								List<IonObject> result = new ArrayList<>(items == null ? 0 : items.size());
								if (items != null)
									for (Object o : items)
										result.add(IonObject.fromJson((JsonObject) o));
								return Future.succeededFuture(PaginatedResult.of(
										body.getLong("page", page), body.getLong("pageSize", pageSize),
										body.getLong("totalItems", (long) result.size()), result));
							} catch (Exception e) {
								return Future.failedFuture(new IonStoreException("Malformed list response", e));
							}
						});
					} else {
						return failFromResponse(response);
					}
				})
				.recover(IonStore::wrapError);

		return ContextualFuture.of(future);
	}

	/**
	 * Deletes an object reference owned by the authenticated user.
	 *
	 * @param id the object reference id (must not be {@code null})
	 * @return a future completing with {@code true} if an object was deleted, {@code false} if none existed
	 */
	public ContextualFuture<Boolean> delete(Id id) {
		Objects.requireNonNull(id, "id");
		closedCheck();

		Future<Boolean> future = httpClient.request(requestOptions(HttpMethod.DELETE, uri("/objects/" + id)))
				.compose(request -> {
					request.putHeader("Authorization", "Bearer " + getAccessToken());
					return request.send();
				})
				.compose(response -> {
					if (response.statusCode() == 204)
						return response.body().map(b -> true);
					else if (response.statusCode() == 404)
						return response.body().map(b -> false);
					else
						return failFromResponse(response);
				})
				.recover(IonStore::wrapError);

		return ContextualFuture.of(future);
	}

	private String uri(String suffix) {
		return basePath + suffix;
	}

	private RequestOptions requestOptions(HttpMethod method, String uri) {
		return new RequestOptions()
				.setMethod(method)
				.setHost(host)
				.setPort(port)
				.setURI(uri)
				.setFollowRedirects(false);
	}

	private String getAccessToken() {
		AccessTokenCache tc = tokenCache;
		if (tc == null || System.currentTimeMillis() - tc.createdAt > ACCESS_TOKEN_TIMEOUT) {
			SignedCwt.Builder builder = SignedCwt.builder(deviceIdentity)
					.subject(userId)
					.audience(servicePeerId)
					.expiration(Duration.ofMillis(ACCESS_TOKEN_TIMEOUT + 1000 * 60))
					.notBeforeNow()
					.issuedAtNow()
					.scope(AccessScope.CLIENT.toString())
					.clientId(deviceIdentity.getId());

			String token = builder.buildToString();
			tc = new AccessTokenCache(token, System.currentTimeMillis());
			tokenCache = tc;
		}

		return tc.token;
	}

	// Server-managed Ion-* headers; mirrors the service's IonStoreHeaders.isReserved. Used on both
	// legs: the service never stores these as object metadata, so neither does the client when it
	// rebuilds an IonObject from a download's response headers.
	@SuppressWarnings("BooleanMethodIsAlwaysInverted")
	private static boolean isReserved(String name) {
		return name.equalsIgnoreCase(ION_TTL) || name.equalsIgnoreCase(ION_ENCRYPTED)
				|| name.equalsIgnoreCase(ION_EXPIRE_AT) || name.equalsIgnoreCase(ION_CONTENT_ID);
	}

	// Ion-* headers the client derives itself on a put and therefore never accepts from caller
	// metadata: the server-managed ones, plus the encryption descriptor, which has to describe how the
	// payload was actually encrypted rather than whatever the caller claims.
	//
	// Deliberately a separate predicate from isReserved: the service treats ION_ENCRYPTION as ordinary
	// metadata and echoes it back on GET, and isReserved is what filters those response headers. Adding
	// ION_ENCRYPTION there would strip the descriptor out of IonObject.getMetadata() - the one place a
	// reader needs to find it in order to decrypt.
	@SuppressWarnings("BooleanMethodIsAlwaysInverted")
	private static boolean isManagedOnPut(String name) {
		return isReserved(name) || name.equalsIgnoreCase(ION_ENCRYPTION);
	}

	// Builds the Ion-Encryption value for a payload framed in encryptedChunkSize-byte ciphertext blocks.
	private static String encryptionDescriptor(int encryptedChunkSize) {
		return ION_ENCRYPTION_SECRETSTREAM + "; " + ION_ENCRYPTION_CHUNK + encryptedChunkSize;
	}

	// Reads back what encryptionDescriptor wrote and returns the ciphertext chunk size to frame
	// decryption with - the value DecryptedWriteStream takes, so no unit conversion at the point of use.
	// Paired with encryptionDescriptor deliberately: the format is written in one place and parsed in
	// another, and this is the seam where they have to agree. Surrounding whitespace and unrecognized
	// parameters are tolerated, since the value travels as an ordinary HTTP header and is expected to
	// grow. An absent descriptor means the object predates it and was framed with CHUNK_SIZE.
	static int parseEncryptionDescriptor(@Nullable String descriptor) throws DecryptionException {
		if (descriptor == null)
			return CHUNK_SIZE;

		String[] parts = descriptor.split(";");
		if (!parts[0].trim().equalsIgnoreCase(ION_ENCRYPTION_SECRETSTREAM))
			throw new DecryptionException("Unsupported encryption scheme: " + descriptor);

		for (int i = 1; i < parts.length; i++) {
			String param = parts[i].trim();
			if (!param.regionMatches(true, 0, ION_ENCRYPTION_CHUNK, 0, ION_ENCRYPTION_CHUNK.length()))
				continue;

			int chunkSize;
			String value = param.substring(ION_ENCRYPTION_CHUNK.length()).trim();
			try {
				chunkSize = Integer.parseInt(value);
			} catch (NumberFormatException e) {
				throw new DecryptionException("Malformed encryption chunk size: " + param);
			}

			// A ciphertext block is a plaintext block plus its authentication tag, so a size at or below
			// the tag size is not something EncryptedReadStream could have produced.
			if (chunkSize <= SecretStream.ABYTES)
				throw new DecryptionException("Invalid encryption chunk size: " + chunkSize);

			return chunkSize;
		}

		throw new DecryptionException("Encryption descriptor carries no chunk size: " + descriptor);
	}

	// Reads and discards the response body (releasing the connection), then fails with the given error.
	private static <T> Future<T> drainAndFail(HttpClientResponse response, Throwable error) {
		return response.body().transform(ar -> Future.failedFuture(error));
	}

	// Reads the error body, parses the service Error payload (type/code/message/nested) into a
	// classified IonStoreException, logs it at a level appropriate to the status, and fails.
	private static <T> Future<T> failFromResponse(HttpClientResponse response) {
		int statusCode = response.statusCode();
		return response.body().transform(ar -> {
			Buffer body = ar.succeeded() ? ar.result() : null;
			IonStoreException error = IonStoreException.fromResponse(statusCode, body, response);

			// Client-correctable conditions (bad request, auth, not found, too large, quota/TTL) are
			// expected and logged at debug; everything else (5xx, federation faults) at error level.
			// The exception's concrete type names the error category.
			if (statusCode >= 400 && statusCode < 500)
				log.debug("Ion-Store request failed: {} [{}/{}] - {}", statusCode,
						error.getClass().getSimpleName(), error.getErrorCode(), error.getMessage());
			else
				log.error("Ion-Store request failed: {} [{}/{}] - {}", statusCode,
						error.getClass().getSimpleName(), error.getErrorCode(), error.getMessage());

			return Future.failedFuture(error);
		});
	}

	private static <T> Future<T> wrapError(Throwable e) {
		// An IonStoreException is already classified and (for HTTP errors) already logged by
		// failFromResponse, so pass it through untouched to avoid duplicate, noisy logging.
		if (e instanceof IonStoreException ise)
			return Future.failedFuture(ise);

		// Anything else is an unexpected transport- or client-side failure (connection/TLS error,
		// malformed response, ...): log it at error and wrap it with no HTTP status.
		log.error("Ion-Store request failed: {}", e.getMessage(), e);
		return Future.failedFuture(new IonStoreException("Ion-Store request failed: " + e.getMessage(), e));
	}

	private Future<Void> closeAndDelete(AsyncFile af, String file) {
		// A rollback can be triggered by a check that runs after the transfer itself succeeded - and
		// pipeTo() ends the destination on success, which for an AsyncFile means closing it. Closing a
		// second time throws rather than failing a future, so without this the exception would escape
		// the rollback: the real error would be replaced by "File handle is closed", and the file that
		// was supposed to be deleted would be left behind.
		Future<Void> closed;
		try {
			closed = af.close();
		} catch (IllegalStateException alreadyClosed) {
			closed = Future.succeededFuture();
		}

		return closed.transform(x -> vertx.fileSystem().delete(file))
				.transform(x -> Future.succeededFuture());
	}

	// Builds a Content-Disposition value: an ASCII-sanitized filename plus an RFC 5987 filename* form
	// for full fidelity when the name contains non-ASCII characters.
	private static String contentDisposition(String name) {
		StringBuilder ascii = new StringBuilder(name.length());
		name.codePoints().forEach(c ->
				ascii.appendCodePoint((c < 0x20 || c > 0x7E || c == '"' || c == '\\') ? '_' : c));

		StringBuilder sb = new StringBuilder("attachment; filename=\"").append(ascii).append('"');
		String encoded = rfc5987Encode(name);
		if (!encoded.contentEquals(ascii))
			sb.append("; filename*=UTF-8''").append(encoded);
		return sb.toString();
	}

	private static String rfc5987Encode(String value) {
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		StringBuilder sb = new StringBuilder(bytes.length);
		for (byte b : bytes) {
			int c = b & 0xFF;
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
					|| c == '-' || c == '.' || c == '_' || c == '~')
				sb.append((char) c);
			else
				sb.append('%').append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xF, 16)))
						.append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
		}
		return sb.toString();
	}

	/**
	 * Extracts the file name from a {@code Content-Disposition} header value, preferring the RFC 5987
	 * {@code filename*=} form over a plain {@code filename=} and reducing the result to its last path
	 * segment. Returns {@code null} when no usable name is present. (Mirrors the service's parser.)
	 */
	private static @Nullable String getFileName(@Nullable String disposition) {
		if (disposition == null)
			return null;

		String plain = null;     // from filename=
		String extended = null;  // from filename*= (RFC 5987), takes precedence

		int i = 0;
		int n = disposition.length();
		while (i < n) {
			while (i < n && (disposition.charAt(i) == ';' || Character.isWhitespace(disposition.charAt(i))))
				i++;

			int nameStart = i;
			while (i < n && disposition.charAt(i) != '=' && disposition.charAt(i) != ';')
				i++;
			if (i >= n || disposition.charAt(i) != '=')
				continue;

			String name = disposition.substring(nameStart, i).trim().toLowerCase();
			i++; // consume '='

			String value;
			if (i < n && disposition.charAt(i) == '"') {
				i++; // consume opening quote
				StringBuilder sb = new StringBuilder();
				while (i < n && disposition.charAt(i) != '"') {
					if (disposition.charAt(i) == '\\' && i + 1 < n)
						i++;
					sb.append(disposition.charAt(i++));
				}
				if (i < n)
					i++; // consume closing quote
				value = sb.toString();
			} else {
				int valStart = i;
				while (i < n && disposition.charAt(i) != ';')
					i++;
				value = disposition.substring(valStart, i).trim();
			}

			if (name.equals("filename"))
				plain = value;
			else if (name.equals("filename*"))
				extended = value;
		}

		String value = extended != null ? decodeRfc5987(extended) : plain;
		if (value == null || value.isEmpty())
			return null;

		int slash = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
		if (slash >= 0)
			value = value.substring(slash + 1);

		return value.isEmpty() ? null : value;
	}

	private static String decodeRfc5987(String value) {
		int firstQuote = value.indexOf('\'');
		int secondQuote = firstQuote >= 0 ? value.indexOf('\'', firstQuote + 1) : -1;
		if (secondQuote < 0)
			return value;

		String charsetName = value.substring(0, firstQuote);
		String encoded = value.substring(secondQuote + 1);

		Charset charset;
		try {
			charset = charsetName.isEmpty() ? StandardCharsets.UTF_8 : Charset.forName(charsetName);
		} catch (Exception e) {
			charset = StandardCharsets.UTF_8;
		}

		ByteArrayOutputStream out = new ByteArrayOutputStream(encoded.length());
		for (int i = 0; i < encoded.length(); i++) {
			char c = encoded.charAt(i);
			if (c == '%' && i + 2 < encoded.length()) {
				try {
					out.write(Integer.parseInt(encoded.substring(i + 1, i + 3), 16));
					i += 2;
					continue;
				} catch (NumberFormatException ignore) {
					// malformed escape: keep the literal '%'
				}
			}
			out.write(c);
		}
		return out.toString(charset);
	}

	/**
	 * Creates a new {@link Builder}.
	 *
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Fluent builder for {@link IonStore}.
	 * <p>
	 * Exactly one authentication mode must be configured: either {@link #userKey(Signature.KeyPair)
	 * userKey} (user-key mode), or {@link #userId(Id) userId} together with
	 * {@link #deviceKey(Signature.KeyPair) deviceKey} (device mode). The service coordinates
	 * {@link #servicePeerId(Id) servicePeerId} and {@link #serviceUrl(URL) serviceUrl} are both
	 * required. Not thread-safe.
	 */
	@NullUnmarked
	public static class Builder {
		private Vertx vertx;
		@SuppressWarnings("unused")
		private Signature.KeyPair userKey;
		private Id userId;
		private Signature.KeyPair deviceKey;
		private Id servicePeerId;
		private URL serviceUrl;

		private Builder() {
			// Try to autoconfigure the Vert.x instance if the builder is created within a Vert.x context.
			this.vertx = Vertx.currentContext() != null ? Vertx.currentContext().owner() : null;
		}

		/**
		 * Sets the Vert.x instance the client will run on.
		 *
		 * @param vertx the Vert.x instance (must not be {@code null})
		 * @return this builder
		 */
		public Builder vertx(Vertx vertx) {
			Objects.requireNonNull(vertx, "vertx");
			this.vertx = vertx;
			return this;
		}

		/**
		 * Sets the user id directly. The device key ({@link #deviceKey}) signs tokens on behalf of this
		 * user. Mutually exclusive with {@link #userKey} (whichever is set last wins).
		 *
		 * @param userId the user id (must not be {@code null})
		 * @return this builder
		 */
		public Builder userId(Id userId) {
			Objects.requireNonNull(userId, "userId");
			this.userId = userId;
			this.userKey = null;
			return this;
		}

		/**
		 * Supplies the user identity from the given user key pair, deriving the user id from it. The
		 * device key ({@link #deviceKey}) still signs the tokens; the user key itself is not used for
		 * signing. Mutually exclusive with {@link #userId} (whichever is set last wins).
		 *
		 * @param key the user key pair (must not be {@code null})
		 * @return this builder
		 */
		public Builder userKey(Signature.KeyPair key) {
			Objects.requireNonNull(key, "key");
			this.userKey = key;
			this.userId = Id.of(key.publicKey().bytes());
			return this;
		}

		/**
		 * Supplies the user identity from an encoded private key string (derives the user id).
		 *
		 * @param privateKey the user private key, either a {@code 0x}-prefixed hex string or a Base58 string
		 * @return this builder
		 */
		public Builder userKey(String privateKey) {
			Objects.requireNonNull(privateKey, "privateKey");
			byte[] sk = privateKey.startsWith("0x") ? Hex.decode(privateKey.substring(2)) : Base58.decode(privateKey);
			return userKey(Signature.KeyPair.fromPrivateKey(sk));
		}

		/**
		 * Supplies the user identity from a raw private key (derives the user id).
		 *
		 * @param privateKey the user private key bytes (must be {@link Signature.PrivateKey#BYTES} long)
		 * @return this builder
		 * @throws IllegalArgumentException if the key length is invalid
		 */
		public Builder userKey(byte[] privateKey) {
			Objects.requireNonNull(privateKey, "privateKey");
			if (privateKey.length != Signature.PrivateKey.BYTES)
				throw new IllegalArgumentException("Invalid private key");
			return userKey(Signature.KeyPair.fromPrivateKey(privateKey));
		}

		/**
		 * Sets the device key pair used to sign tokens (required). The user is identified separately
		 * via {@link #userKey} or {@link #userId}.
		 *
		 * @param key the device key pair (must not be {@code null})
		 * @return this builder
		 */
		public Builder deviceKey(Signature.KeyPair key) {
			Objects.requireNonNull(key, "key");
			this.deviceKey = key;
			return this;
		}

		/**
		 * Sets the device key from an encoded private key string.
		 *
		 * @param privateKey the device private key, either a {@code 0x}-prefixed hex string or a Base58 string
		 * @return this builder
		 */
		public Builder deviceKey(String privateKey) {
			Objects.requireNonNull(privateKey, "privateKey");
			byte[] sk = privateKey.startsWith("0x") ? Hex.decode(privateKey.substring(2)) : Base58.decode(privateKey);
			return deviceKey(Signature.KeyPair.fromPrivateKey(sk));
		}

		/**
		 * Sets the device key from a raw private key.
		 *
		 * @param privateKey the device private key bytes (must be {@link Signature.PrivateKey#BYTES} long)
		 * @return this builder
		 * @throws IllegalArgumentException if the key length is invalid
		 */
		public Builder deviceKey(byte[] privateKey) {
			Objects.requireNonNull(privateKey, "privateKey");
			if (privateKey.length != Signature.PrivateKey.BYTES)
				throw new IllegalArgumentException("Invalid private key");
			return deviceKey(Signature.KeyPair.fromPrivateKey(privateKey));
		}

		/**
		 * Sets the peer id of the target Ion Store service. Over HTTPS the service's self-signed
		 * certificate is pinned to this peer id.
		 *
		 * @param id the service peer id (must not be {@code null})
		 * @return this builder
		 */
		public Builder servicePeerId(Id id) {
			Objects.requireNonNull(id, "servicePeerId");
			this.servicePeerId = id;
			return this;
		}

		/**
		 * Sets the base URL of the target Ion Store service.
		 *
		 * @param url an {@code http} or {@code https} URL (must not be {@code null})
		 * @return this builder
		 * @throws IllegalArgumentException if the URL uses a non-http(s) protocol
		 */
		public Builder serviceUrl(URL url) {
			Objects.requireNonNull(url, "url");
			if (!url.getProtocol().equals("http") && !url.getProtocol().equals("https"))
				throw new IllegalArgumentException("Invalid service URL protocol (must be http or https): " + url.getProtocol());
			this.serviceUrl = url;
			return this;
		}

		/**
		 * Sets the base URL of the target Ion Store service from a string.
		 *
		 * @param url an {@code http} or {@code https} URL (must not be {@code null})
		 * @return this builder
		 * @throws IllegalArgumentException if the URL is malformed or uses a non-http(s) protocol
		 */
		public Builder serviceUrl(String url) {
			Objects.requireNonNull(url, "url");
			try {
				return serviceUrl(new URL(url));
			} catch (MalformedURLException e) {
				throw new IllegalArgumentException("Invalid service URL: " + url, e);
			}
		}

		/**
		 * Validates the configuration and builds the {@link IonStore} client.
		 *
		 * @return the configured client
		 * @throws IllegalStateException if the {@code deviceKey}, the user identity ({@code userKey} or
		 *         {@code userId}), {@code servicePeerId}, or {@code serviceUrl} is missing
		 */
		public IonStore build() {
			try {
				return new IonStore(this);
			} catch (NullPointerException | IllegalArgumentException e) {
				throw new IllegalStateException("Invalid IonStore configuration: " + e.getMessage(), e);
			}
		}
	}
}
