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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import io.vertx.core.Future;
import io.vertx.core.Handler;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bosonnetwork.Id;
import io.bosonnetwork.Identity;
import io.bosonnetwork.crypto.CryptoIdentity;
import io.bosonnetwork.crypto.Hash;
import io.bosonnetwork.crypto.HybridTrustManager;
import io.bosonnetwork.crypto.Signature;
import io.bosonnetwork.cwt.SignedCwt;
import io.bosonnetwork.ionstore.exceptions.IonStoreException;
import io.bosonnetwork.ionstore.exceptions.ObjectIntegrityException;
import io.bosonnetwork.service.AccessScope;
import io.bosonnetwork.utils.Base58;
import io.bosonnetwork.utils.Hex;
import io.bosonnetwork.vertx.AsyncInputStream;
import io.bosonnetwork.vertx.AsyncOutputStream;
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
 * content id covers the whole object, ranged downloads are intentionally not offered — a partial body
 * cannot be verified.
 *
 * <h2>Authentication</h2>
 * Object retrieval is permissionless and sends no token. Upload, list, and delete carry a short-lived
 * {@link SignedCwt CWT} bearer token, minted in one of two mutually exclusive modes selected at build
 * time: <b>user-key mode</b> ({@link Builder#userKey}) or <b>device mode</b> ({@link Builder#userId}
 * + {@link Builder#deviceKey}). Over HTTPS the service's self-signed certificate is pinned to its
 * peer id.
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
	private static final String API_PREFIX = "/v1";

	// Size threshold for the byte[] put: arrays smaller than this are copied into a single buffer and
	// sent in one shot; larger arrays are streamed from the array (see put(byte[], PutOptions)).
	private static final int IN_MEMORY_PUT_THRESHOLD = 1024 * 1024; // 1 MiB

	// Ion-* header names (mirrors the service's IonStoreHeaders; redeclared here to avoid depending
	// on the service module).
	private static final String ION_HEADER_PREFIX = "Ion-";
	private static final String ION_TTL = "Ion-TTL";
	private static final String ION_ENCRYPTED = "Ion-Encrypted";
	private static final String ION_EXPIRE_AT = "Ion-Expire-At";
	private static final String ION_CONTENT_ID = "Ion-Content-Id";

	private final Vertx vertx;

	// The active signing identity used for access tokens: the user identity in user-key mode, or the
	// device identity in device mode.
	private final Identity identity;
	private final Id userId;
	private final Identity deviceIdentity;

	private final Id servicePeerId;
	private final URL serviceUrl;

	private final String host;
	private final int port;
	// Service URL path (sans trailing slash) plus the API version prefix; all request URIs append to it.
	private final String basePath;

	private final HttpClient httpClient;
	private volatile AccessTokenCache tokenCache;

	private volatile boolean closed;

	private static final Logger log = LoggerFactory.getLogger(IonStore.class);

	private record AccessTokenCache(String token, long createdAt) {}

	private IonStore(Vertx vertx, Signature.KeyPair userKey, Id userId, Signature.KeyPair deviceKey,
					 Id servicePeerId, URL serviceUrl) {
		this.vertx = vertx;
		if (userKey != null) {
			Identity userIdentity = new CryptoIdentity(userKey);
			this.identity = userIdentity;
			this.userId = userIdentity.getId();
			this.deviceIdentity = null;
		} else {
			this.deviceIdentity = new CryptoIdentity(deviceKey);
			this.identity = deviceIdentity;
			this.userId = userId;
		}

		this.servicePeerId = servicePeerId;
		this.serviceUrl = serviceUrl;

		boolean ssl = serviceUrl.getProtocol().equals("https");
		this.host = serviceUrl.getHost();
		this.port = serviceUrl.getPort() > 0 ? serviceUrl.getPort() : serviceUrl.getDefaultPort();

		String path = serviceUrl.getPath();
		if (path == null)
			path = "";
		if (path.endsWith("/"))
			path = path.substring(0, path.length() - 1);
		this.basePath = path + API_PREFIX;

		PoolOptions poolOptions = new PoolOptions()
				.setHttp1MaxSize(16)
				.setMaxWaitQueueSize(1_000);

		HttpClientOptions options = new HttpClientOptions()
				.setSsl(ssl)
				.setDefaultHost(host)
				.setDefaultPort(port)
				.setKeepAlive(true)
				.setPipelining(false)            // safer for large streaming responses
				.setMaxChunkSize(16 * 1024)      // 16 KB chunks (balanced default)
				.setDecompressionSupported(false) // avoid buffering for transparent decompression
				.setConnectTimeout(10_000)
				.setIdleTimeout(60)
				.setIdleTimeoutUnit(TimeUnit.SECONDS)
				.setProtocolVersion(HttpVersion.HTTP_1_1);

		if (ssl)
			options.setEnabledSecureTransportProtocols(Set.of("TLSv1.3"))
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
	 * Returns the device id this client signs tokens with in device mode, or {@code null} in user-key
	 * mode.
	 *
	 * @return the device id, or {@code null} in user-key mode
	 */
	public Id getDeviceId() {
		return deviceIdentity != null ? deviceIdentity.getId() : null;
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

	/**
	 * Stores an object by streaming the contents of a blocking {@link InputStream}.
	 * <p>
	 * The stream is consumed on a worker thread and is <b>not</b> closed by this method: the caller
	 * retains ownership and must close it once the returned future completes.
	 *
	 * @param content the object payload as a blocking input stream (must not be {@code null})
	 * @param length  the payload length in bytes, or a negative value if unknown (sends chunked)
	 * @param options the put options (must not be {@code null}; use {@link PutOptions#none()})
	 * @return a future completing with the stored object's metadata
	 */
	public ContextualFuture<IonObject> put(InputStream content, long length, PutOptions options) {
		Objects.requireNonNull(content, "content");
		Objects.requireNonNull(options, "options");
		closedCheck();
		return put(new AsyncInputStream(vertx, content, 8192, false), length, options);
	}

	/**
	 * Stores an object by streaming the given content.
	 *
	 * @param content the object payload as a read stream (must not be {@code null})
	 * @param length  the payload length in bytes, or a negative value if unknown (sends chunked)
	 * @param options the put options (must not be {@code null}; use {@link PutOptions#none()})
	 * @return a future completing with the stored object's metadata
	 */
	public ContextualFuture<IonObject> put(ReadStream<Buffer> content, long length, PutOptions options) {
		Objects.requireNonNull(content, "content");
		Objects.requireNonNull(options, "options");
		closedCheck();
		return ContextualFuture.of(upload(content, length, options));
	}

	/**
	 * Stores an object from a byte array.
	 * <p>
	 * The array is consumed asynchronously: small payloads are copied up front, but larger ones are
	 * read from {@code content} as the upload streams. The caller must therefore not modify
	 * {@code content} until the returned future completes.
	 *
	 * @param content the object payload (must not be {@code null})
	 * @param options the put options (must not be {@code null}; use {@link PutOptions#none()})
	 * @return a future completing with the stored object's metadata
	 */
	public ContextualFuture<IonObject> put(byte[] content, PutOptions options) {
		Objects.requireNonNull(content, "content");
		Objects.requireNonNull(options, "options");
		closedCheck();

		// The array is already wholly in memory, so streaming it does not reduce the caller's footprint
		// — it only avoids the single extra copy that Buffer.buffer makes, at the cost of per-chunk
		// worker-thread hops. That trade-off only pays off for large arrays, so copy-and-send below the
		// threshold and stream above it.
		if (content.length < IN_MEMORY_PUT_THRESHOLD)
			return put(Buffer.buffer(content), options); // Buffer.buffer copies the array
		else
			return put(new ByteArrayInputStream(content), content.length, options);
	}

	/**
	 * Stores an object held entirely in memory.
	 *
	 * @param content the object payload (must not be {@code null})
	 * @param options the put options (must not be {@code null}; use {@link PutOptions#none()})
	 * @return a future completing with the stored object's metadata
	 */
	public ContextualFuture<IonObject> put(Buffer content, PutOptions options) {
		Objects.requireNonNull(content, "content");
		Objects.requireNonNull(options, "options");
		closedCheck();

		Future<IonObject> future = httpClient.request(requestOptions(HttpMethod.POST, uri("/objects")))
				.compose(request -> {
					applyUploadHeaders(request, options, content.length());
					return request.send(content);
				})
				.compose(this::handleUploadResponse)
				.recover(IonStore::wrapError);

		return ContextualFuture.of(future);
	}


	/**
	 * Stores an object by streaming the contents of a file. When the options do not specify a name or
	 * content type, they default to the file's name and its probed MIME type.
	 *
	 * @param file    the file to store (must not be {@code null})
	 * @param options the put options (must not be {@code null}; use {@link PutOptions#none()})
	 * @return a future completing with the stored object's metadata
	 */
	public ContextualFuture<IonObject> put(Path file, PutOptions options) {
		Objects.requireNonNull(file, "file");
		Objects.requireNonNull(options, "options");
		closedCheck();

		long length;
		String probedType;
		try {
			length = Files.size(file);
			probedType = Files.probeContentType(file);
		} catch (IOException e) {
			return ContextualFuture.failedFuture(new IonStoreException("Cannot read file: " + file, e));
		}

		PutOptions.Builder b = PutOptions.builder()
				.ttl(options.getTtl())
				.encrypted(options.isEncrypted())
				.metadata(options.getMetadata())
				.name(options.getName() != null ? options.getName() : file.getFileName().toString());
		String contentType = options.getContentType() != null ? options.getContentType() : probedType;
		if (contentType != null)
			b.contentType(contentType);
		PutOptions effective = b.build();

		Future<IonObject> future = vertx.fileSystem()
				.open(file.toString(), new OpenOptions().setRead(true).setWrite(false))
				.compose(af -> {
					// Close the source file once the upload settles, then propagate its original outcome.
					Future<IonObject> upload = upload(af, length, effective);
					return upload.transform(ar -> af.close().transform(x -> ar.succeeded() ?
							Future.succeededFuture(ar.result()) : Future.failedFuture(ar.cause())));
				});

		return ContextualFuture.of(future);
	}

	private Future<IonObject> upload(ReadStream<Buffer> content, long length, PutOptions options) {
		return httpClient.request(requestOptions(HttpMethod.POST, uri("/objects")))
				.compose(request -> {
					applyUploadHeaders(request, options, length);
					return request.send(content);
				})
				.compose(this::handleUploadResponse)
				.recover(IonStore::wrapError);
	}

	private void applyUploadHeaders(HttpClientRequest request, PutOptions options, long length) {
		request.putHeader("Authorization", "Bearer " + getAccessToken());
		request.putHeader("Content-Type", options.getContentType() != null ?
				options.getContentType() : "application/octet-stream");
		if (options.getName() != null)
			request.putHeader("Content-Disposition", contentDisposition(options.getName()));
		if (options.getTtl() > 0)
			request.putHeader(ION_TTL, Long.toString(options.getTtl()));
		if (options.isEncrypted())
			request.putHeader(ION_ENCRYPTED, "true");
		options.getMetadata().forEach((k, v) -> {
			String name = k.regionMatches(true, 0, ION_HEADER_PREFIX, 0, ION_HEADER_PREFIX.length()) ?
					k : ION_HEADER_PREFIX + k;
			// never let custom metadata override the reserved/server-managed headers
			if (!isReserved(name))
				request.putHeader(name, String.valueOf(v));
		});

		if (length >= 0)
			request.putHeader("Content-Length", Long.toString(length));
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

	/**
	 * Retrieves an object, streaming the integrity-verified payload to the given blocking
	 * {@link OutputStream}.
	 * <p>
	 * The stream is written on a worker thread, flushed when the transfer completes, and <b>not</b>
	 * closed by this method: the caller retains ownership. Note that, unlike the file variant, the
	 * destination cannot be rolled back — if the integrity check fails, the (corrupt) bytes will
	 * already have been written before the returned future fails.
	 *
	 * @param id  the object reference id (must not be {@code null})
	 * @param dst the destination output stream (must not be {@code null})
	 * @return a future completing with the object metadata, or {@code null} if the object was not found
	 */
	public ContextualFuture<IonObject> get(Id id, OutputStream dst) {
		Objects.requireNonNull(id, "id");
		Objects.requireNonNull(dst, "dst");
		return get(id, new AsyncOutputStream(vertx, dst, false));
	}

	/**
	 * Retrieves a federated object, streaming the integrity-verified payload to the given blocking
	 * {@link OutputStream} (see {@link #get(Id, OutputStream)} and {@link #get(Id, Id, WriteStream)}).
	 *
	 * @param peerId the peer id of the Ion Store node holding the object (must not be {@code null})
	 * @param id     the object reference id (must not be {@code null})
	 * @param dst    the destination output stream (must not be {@code null})
	 * @return a future completing with the object metadata, or {@code null} if the object was not found
	 */
	public ContextualFuture<IonObject> get(Id peerId, Id id, OutputStream dst) {
		Objects.requireNonNull(peerId, "peerId");
		Objects.requireNonNull(id, "id");
		Objects.requireNonNull(dst, "dst");
		return get(peerId, id, new AsyncOutputStream(vertx, dst, false));
	}

	/**
	 * Retrieves an object, streaming the integrity-verified payload to the given WriteStream.
	 * <p>
	 * The destination is ended when the transfer completes. The returned metadata is derived from the
	 * response headers (its {@code name}/{@code contentType} may be {@code null} if the service did not
	 * advertise them).
	 *
	 * @param id  the object reference id (must not be {@code null})
	 * @param dst the destination write stream (must not be {@code null})
	 * @return a future completing with the object metadata, or {@code null} if the object was not found
	 */
	public ContextualFuture<IonObject> get(Id id, WriteStream<Buffer> dst) {
		Objects.requireNonNull(id, "id");
		Objects.requireNonNull(dst, "dst");
		closedCheck();
		return ContextualFuture.of(download(uri("/objects/" + id), servicePeerId, id, dst).recover(IonStore::wrapError));
	}

	/**
	 * Retrieves an object held by a remote peer (federation), streaming the integrity-verified payload
	 * to the given WriteStream. The bound service fetches and caches the object from the named peer.
	 *
	 * @param peerId the peer id of the Ion Store node holding the object (must not be {@code null})
	 * @param id     the object reference id (must not be {@code null})
	 * @param dst    the destination write stream (must not be {@code null})
	 * @return a future completing with the object metadata, or {@code null} if the object was not found
	 */
	public ContextualFuture<IonObject> get(Id peerId, Id id, WriteStream<Buffer> dst) {
		Objects.requireNonNull(peerId, "peerId");
		Objects.requireNonNull(id, "id");
		Objects.requireNonNull(dst, "dst");
		closedCheck();
		return ContextualFuture.of(download(uri("/objects/" + peerId + "/" + id), peerId, id, dst).recover(IonStore::wrapError));
	}

	/**
	 * Retrieves an object to a file. The integrity-verified payload is written to {@code file}; on any
	 * failure (including an integrity mismatch) or when the object is not found, the file is removed.
	 *
	 * @param id   the object reference id (must not be {@code null})
	 * @param file the destination file (must not be {@code null})
	 * @return a future completing with the object metadata, or {@code null} if the object was not found
	 */
	public ContextualFuture<IonObject> get(Id id, Path file) {
		Objects.requireNonNull(id, "id");
		Objects.requireNonNull(file, "file");
		closedCheck();
		return ContextualFuture.of(downloadToFile(uri("/objects/" + id), servicePeerId, id, file).recover(IonStore::wrapError));
	}

	/**
	 * Retrieves a federated object to a file (see {@link #get(Id, Path)} and
	 * {@link #get(Id, Id, WriteStream)}).
	 *
	 * @param peerId the peer id of the Ion Store node holding the object (must not be {@code null})
	 * @param id     the object reference id (must not be {@code null})
	 * @param file   the destination file (must not be {@code null})
	 * @return a future completing with the object metadata, or {@code null} if the object was not found
	 */
	public ContextualFuture<IonObject> get(Id peerId, Id id, Path file) {
		Objects.requireNonNull(peerId, "peerId");
		Objects.requireNonNull(id, "id");
		Objects.requireNonNull(file, "file");
		closedCheck();
		return ContextualFuture.of(downloadToFile(uri("/objects/" + peerId + "/" + id), peerId, id, file).recover(IonStore::wrapError));
	}

	/**
	 * Retrieves an object into memory, returning a {@link BytesIonObject} that carries both the
	 * metadata and the integrity-verified payload. Prefer a streaming variant for large objects.
	 *
	 * @param id the object reference id (must not be {@code null})
	 * @return a future completing with the in-memory object, or {@code null} if it was not found
	 */
	public ContextualFuture<BytesIonObject> get(Id id) {
		Objects.requireNonNull(id, "id");
		closedCheck();
		return ContextualFuture.of(downloadToMemory(uri("/objects/" + id), servicePeerId, id).recover(IonStore::wrapError));
	}

	/**
	 * Retrieves a federated object into memory (see {@link #get(Id)} and
	 * {@link #get(Id, Id, WriteStream)}).
	 *
	 * @param peerId the peer id of the Ion Store node holding the object (must not be {@code null})
	 * @param id     the object reference id (must not be {@code null})
	 * @return a future completing with the in-memory object, or {@code null} if it was not found
	 */
	public ContextualFuture<BytesIonObject> get(Id peerId, Id id) {
		Objects.requireNonNull(peerId, "peerId");
		Objects.requireNonNull(id, "id");
		closedCheck();
		return ContextualFuture.of(downloadToMemory(uri("/objects/" + peerId + "/" + id), peerId, id).recover(IonStore::wrapError));
	}

	private Future<BytesIonObject> downloadToMemory(String uri, Id ownerPeerId, Id id) {
		BufferWriteStream ws = new BufferWriteStream();
		return download(uri, ownerPeerId, id, ws)
				.map(meta -> meta == null ? null : new BytesIonObject(meta, ws.toBuffer()));
	}

	private Future<IonObject> downloadToFile(String uri, Id ownerPeerId, Id id, Path file) {
		String fp = file.toString();
		return vertx.fileSystem()
				.open(fp, new OpenOptions().setWrite(true).setCreate(true).setTruncateExisting(true))
				.compose(af -> download(uri, ownerPeerId, id, af)
						.recover(e -> closeAndDelete(af, fp).transform(x -> Future.failedFuture(e)))
						.compose(meta -> meta != null ?
								Future.succeededFuture(meta) :
								closeAndDelete(af, fp).mapEmpty()));
	}

	// Streams the verified payload to dst. On HTTP 200 the content is hashed while piping and checked
	// against the advertised Ion-Content-Id; on 404 the body is drained and null is returned.
	private Future<IonObject> download(String uri, Id ownerPeerId, Id id, WriteStream<Buffer> dst) {
		return httpClient.request(requestOptions(HttpMethod.GET, uri))
				.compose(HttpClientRequest::send)
				.compose(response -> {
					int statusCode = response.statusCode();
					if (statusCode == 200) {
						String cid = response.headers().get(ION_CONTENT_ID);
						if (cid == null)
							return drainAndFail(response, new ObjectIntegrityException("Missing Ion-Content-Id header"));
						Id expectedContentId;
						try {
							expectedContentId = Id.of(cid);
						} catch (IllegalArgumentException e) {
							return drainAndFail(response, new ObjectIntegrityException("Malformed Ion-Content-Id header: " + cid));
						}

						MessageDigest md = Hash.sha256();
						AtomicLong size = new AtomicLong();
						ReadStream<Buffer> observed = new ObservableReadStream<>(response, buf -> {
							md.update(buf.getBytes());
							size.addAndGet(buf.length());
						});

						return observed.pipeTo(dst).compose(v -> {
							Id actualContentId = Id.of(md.digest());
							if (!actualContentId.equals(expectedContentId))
								return Future.failedFuture(new ObjectIntegrityException(
										"Integrity check failed for object " + id + ": expected content id " +
												expectedContentId + ", computed " + actualContentId));
							return Future.succeededFuture(
									ionObjectFromHeaders(ownerPeerId, id, response, size.get()));
						});
					} else if (statusCode == 404) {
						return Future.succeededFuture();
					} else {
						return failFromResponse(response);
					}
				});
	}

	private IonObject ionObjectFromHeaders(Id ownerPeerId, Id id, HttpClientResponse response, long size) {
		Id contentId = Id.of(response.headers().get(ION_CONTENT_ID));
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
	public ContextualFuture<IonObject> getIonObject(Id id) {
		Objects.requireNonNull(id, "id");
		closedCheck();

		Future<IonObject> future = httpClient.request(requestOptions(HttpMethod.GET, uri("/objects/" + id)))
				.compose(request -> {
					request.putHeader("Accept", "application/json");
					return request.send();
				})
				.compose(response -> {
					if (response.statusCode() == 200) {
						return response.body().compose(buf -> {
							try {
								return Future.succeededFuture(IonObject.fromJson(new JsonObject(buf)));
							} catch (Exception e) {
								return Future.failedFuture(new IonStoreException("Malformed metadata response", e));
							}
						});
					} else if (response.statusCode() == 404) {
						return Future.succeededFuture();
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
			SignedCwt.Builder builder = SignedCwt.builder(identity)
					.subject(userId)
					.audience(servicePeerId)
					.expiration(Duration.ofMillis(ACCESS_TOKEN_TIMEOUT + 1000 * 60))
					.notBeforeNow()
					.issuedAtNow()
					.scope(AccessScope.CLIENT.toString());
			if (deviceIdentity != null)
				builder.clientId(deviceIdentity.getId());

			String token = builder.buildToString();
			tc = new AccessTokenCache(token, System.currentTimeMillis());
			tokenCache = tc;
		}

		return tc.token;
	}

	@SuppressWarnings("BooleanMethodIsAlwaysInverted")
	private static boolean isReserved(String name) {
		return name.equalsIgnoreCase(ION_TTL) || name.equalsIgnoreCase(ION_ENCRYPTED)
				|| name.equalsIgnoreCase(ION_EXPIRE_AT) || name.equalsIgnoreCase(ION_CONTENT_ID);
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
			IonStoreException error = IonStoreException.fromResponse(statusCode, body);

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
		return af.close()
				.transform(x -> vertx.fileSystem().delete(file))
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
	private static String getFileName(String disposition) {
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
	public static class Builder {
		private Vertx vertx;
		private Signature.KeyPair userKey;
		private Id userId;
		private Signature.KeyPair deviceKey;
		private Id servicePeerId;
		private URL serviceUrl;

		private Builder() {
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
		 * Selects user-key mode using the given user key pair (the client signs tokens as the user).
		 * Mutually exclusive with device mode ({@link #userId}/{@link #deviceKey}).
		 *
		 * @param key the user key pair (must not be {@code null})
		 * @return this builder
		 */
		public Builder userKey(Signature.KeyPair key) {
			Objects.requireNonNull(key, "key");
			this.userKey = key;
			return this;
		}

		/**
		 * Selects user-key mode from an encoded private key string.
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
		 * Selects user-key mode from a raw private key.
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
		 * Sets the user id for device mode. Used together with {@link #deviceKey}: the device signs
		 * tokens on behalf of this user.
		 *
		 * @param userId the user id (must not be {@code null})
		 * @return this builder
		 */
		public Builder userId(Id userId) {
			Objects.requireNonNull(userId, "userId");
			this.userId = userId;
			return this;
		}

		/**
		 * Selects device mode using the given device key pair. Used together with {@link #userId}.
		 * Mutually exclusive with user-key mode ({@link #userKey}).
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
		 * Selects device mode from an encoded private key string.
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
		 * Selects device mode from a raw private key.
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
		 * @throws IllegalStateException if no authentication mode is configured, if {@code deviceKey} is
		 *         used without a {@code userId}, or if {@code servicePeerId} or {@code serviceUrl} is missing
		 */
		public IonStore build() {
			if (userKey == null && deviceKey == null)
				throw new IllegalStateException("Either userKey (user mode) or deviceKey (device mode) must be set");

			if (userKey == null && userId == null)
				throw new IllegalStateException("userId is required in device mode (when userKey is not set)");

			if (servicePeerId == null)
				throw new IllegalStateException("Service peer ID not set");

			if (serviceUrl == null)
				throw new IllegalStateException("Service URL not set");

			Vertx v = vertx != null ? vertx : Vertx.currentContext() != null ? Vertx.currentContext().owner() : null;
			if (v == null)
				throw new IllegalStateException("Vertx not set and no current Vert.x context available");

			return new IonStore(v, userKey, userId, deviceKey, servicePeerId, serviceUrl);
		}
	}

	// A minimal in-memory WriteStream<Buffer> used by the in-memory download variants.
	private static final class BufferWriteStream implements WriteStream<Buffer> {
		private final Buffer buffer = Buffer.buffer();

		Buffer toBuffer() {
			return buffer;
		}

		@Override
		public WriteStream<Buffer> exceptionHandler(Handler<Throwable> handler) {
			return this;
		}

		@Override
		public Future<Void> write(Buffer data) {
			buffer.appendBuffer(data);
			return Future.succeededFuture();
		}

		@Override
		public Future<Void> end() {
			return Future.succeededFuture();
		}

		@Override
		public WriteStream<Buffer> setWriteQueueMaxSize(int maxSize) {
			return this;
		}

		@Override
		public boolean writeQueueFull() {
			return false;
		}

		@Override
		public WriteStream<Buffer> drainHandler(Handler<Void> handler) {
			return this;
		}
	}
}