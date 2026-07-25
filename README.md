# Boson Ion Store Client

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://adoptium.net/)
[![Maven](https://img.shields.io/badge/Maven-3.8%2B-red.svg)](https://maven.apache.org/)

The Java client library for the **Boson Ion Store** service — a content-addressed, deduplicated binary object store with per-object metadata, TTL, per-user quota, and cross-node federation.

The client (`IonStore`) talks to the service over its HTTP API and, unlike a `WebClient`-based client, is built on the lower-level Vert.x `HttpClient` so that arbitrary-size object payloads are **streamed incrementally** instead of being buffered whole in memory.

---

## Table of Contents

- [What Is Ion Store?](#what-is-ion-store)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Adding as a Dependency](#adding-as-a-dependency)
- [Usage](#usage)
  - [Create a client](#create-a-client)
  - [Put (store an object)](#put-store-an-object)
  - [Get (retrieve an object)](#get-retrieve-an-object)
  - [Encryption](#encryption)
  - [Metadata, listing, existence, deletion](#metadata-listing-existence-deletion)
  - [Federation](#federation)
- [API Overview](#api-overview)
- [Integrity](#integrity)
- [Error Handling](#error-handling)
- [Contributing](#contributing)
- [License](#license)

---

## What Is Ion Store?

Ion Store is a Boson layer-2 service that stores binary objects addressed by content. Every object carries **two distinct ids**:

| Id | Meaning |
|---|---|
| **reference id** (`IonObject.getId()`) | A random, per-reference id used to address the object — the value embedded in `ions://<peerId>/<id>` URIs. |
| **content id** (`IonObject.getContentId()`) | The **SHA-256 of the bytes**. Used for integrity verification and server-side deduplication; several references may share one content id. |

Each object also has an optional file name, content type, TTL (lifetime), an `encrypted` flag, and arbitrary custom `Ion-*` metadata. Storage is subject to a per-user quota, and objects can be fetched from a remote Ion Store node through the service (federation).

---

## Features

- **Fluent** builder-style API: **`put()`** to store, **`get(id)`** to retrieve — configure the request, then pick a source (`put`) or a destination (`get`).
- Payload sources/sinks: `byte[]`, Vert.x `Buffer`, `java.nio.file.Path`, `java.io.InputStream`/`OutputStream`, and Vert.x `ReadStream`/`WriteStream`.
- Optional **client-side encryption** (`put().encrypt(key)`) and transparent **decryption** (`get(id).decrypt(key)`), or take the stored bytes verbatim with `get(id).raw()`.
- **Integrity-checked** downloads (SHA-256 vs `Ion-Content-Id`).
- Object **metadata**, **existence check**, paginated **listing**, and **deletion**.
- **Federated** retrieval from a named peer node.
- Asynchronous, non-blocking, Vert.x `Future`-based API.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Java JDK | 17 or later |
| Apache Maven | 3.8 or later |
| Boson Core (`boson-api`) | same version or compatible |
| A running Boson super node hosting the Ion Store service | — |

---

## Build

```bash
git clone https://github.com/bosonnetwork/Boson.IonStore.Client.git
cd Boson.IonStore.Client
mvn clean package
```

To skip tests:

```bash
mvn clean package -DskipTests
```

---

## Adding as a Dependency

```xml
<dependency>
    <groupId>io.bosonnetwork</groupId>
    <artifactId>boson-ion-store-client</artifactId>
    <version>${boson.version}</version>
</dependency>
```

---

## Usage

The client is ready to use as soon as it is built (the underlying `HttpClient` is created in the constructor) — there is no `start()`. Call `close()` when finished. All operations return a `ContextualFuture` (a `CompletableFuture` that completes on the caller's Vert.x context).

### Create a client

**User-key mode** — when the application holds the full user private key:

```java
Id servicePeerId = Id.of("GbRwG3WgKgApSDBr9FGo5Y3RssSWxfWhanXMBdPCo5F2");

IonStore store = IonStore.builder()
        .userKey("<Base58-or-0x-hex-Ed25519-private-key>")
        .servicePeerId(servicePeerId)
        .serviceUrl("https://ionstore.example.com:8443")
        .build();
```

**Device mode** — when the full user key should not live on the device:

```java
IonStore store = IonStore.builder()
        .userId(Id.of("<Base58-user-public-key>"))
        .deviceKey("<Base58-device-private-key>")
        .servicePeerId(servicePeerId)
        .serviceUrl("https://ionstore.example.com:8443")
        .build();
```

Provide an external `Vertx` with `.vertx(vertx)`; if omitted, the current Vert.x context's instance is used, so building outside a Vert.x context requires `.vertx(...)`. When done:

```java
store.close().get();
```

### Put (store an object)

`put()` opens a fluent `PutRequest`: describe the object (name, content type, TTL in seconds, custom `Ion-*` metadata, optional encryption), name exactly one payload source with `content(...)`, then call `send()`. It completes with the stored object's metadata as an `IonObject`. Setters are order-independent; a later `content(...)` replaces an earlier one.

```java
// From a byte array
IonObject obj = store.put()
        .name("hello.txt")
        .contentType("text/plain")
        .ttl(3600)                       // seconds; capped by the service maximum, 0 = service default
        .metadata("Ion-Tag", "greeting") // custom Ion-* metadata (the Ion- prefix is added if missing)
        .content("hello".getBytes(StandardCharsets.UTF_8))
        .send()
        .get();
System.out.println(obj.getId());        // reference id, for ions:// addressing
System.out.println(obj.getContentId()); // SHA-256 content id
System.out.println(obj.getUri());       // ions://<peerId>/<id>

// From a file (name/content type default to the file's own)
IonObject fromFile = store.put().content(Path.of("/data/photo.jpg")).send().get();

// From a Buffer, a blocking InputStream, or any Vert.x ReadStream<Buffer>
store.put().content(Buffer.buffer(bytes)).send();
store.put().content(inputStream).contentLength(len /* omit if unknown */).send();
```

> **Payload ownership.** A put is asynchronous and the payload is generally **not** copied — it is read as the upload streams — so leave the source alone until the returned future completes: do not modify the array/buffer, do not touch the file, and do not read from the stream. By default the client does **not** close a supplied `InputStream`; pass `content(stream, true)` to hand ownership over. A `ReadStream` is consumed but not closed. The `contentLength(...)` hint applies only to the stream sources (the array, buffer, and file sources measure themselves).

### Get (retrieve an object)

Retrieval is permissionless. `get(id)` opens a fluent `GetRequest`. Unlike `put()`, a get has no separate terminal call — naming the destination **is** the terminal operation, because once the destination is known there is nothing left to configure. Every result is an `Optional`, empty when the object does not exist.

The `toBytes()` destination loads the integrity-verified payload into memory and returns a `BytesIonObject` (an `IonObject` that also carries its payload):

```java
Optional<BytesIonObject> result = store.get(id).toBytes().get();
result.ifPresent(obj -> {
    byte[] bytes = obj.getBytes();       // or obj.getContent() for a Buffer
    System.out.println(obj.getContentId() + " / " + obj.getSize());
});
```

For large objects, stream straight to a destination instead of buffering — a file, a blocking `OutputStream`, a Vert.x `WriteStream<Buffer>`, or a caller-supplied `Buffer` to append to. These complete with the object's `IonObject` metadata (empty if not found):

```java
// To a file - the partial file is removed on any failure (including an integrity mismatch)
store.get(id).toFile(Path.of("/tmp/out.bin")).get();

// To a blocking OutputStream; by default the client does NOT close it.
// Pass toOutputStream(stream, true) to have the client close it when the transfer ends.
store.get(id).toOutputStream(outputStream).get();

// Append to a caller-owned Buffer (only metadata is returned; the payload is in your buffer)
Buffer sink = Buffer.buffer();
store.get(id).toBuffer(sink).get();
```

### Encryption

The payload can be encrypted client-side so the service only ever sees ciphertext. Supply a `SecretStream.KEY_BYTES`-byte key to `put().encrypt(key)`; the key never leaves the client. The stored object is flagged `Ion-Encrypted` and carries an `Ion-Encryption` descriptor (scheme + chunk size), so it stays decryptable even if the client's defaults change later.

```java
byte[] key = Random.randomBytes(SecretStream.KEY_BYTES);   // keep this; the service cannot recover it

IonObject stored = store.put().content(plaintext).encrypt(key).send().get();
stored.isEncrypted();         // true
stored.getSize();             // the stored (ciphertext) length
stored.getPlainTextSize();    // the original plaintext length
```

To read it back, hand the same key to `get(id).decrypt(key)` — the payload is decrypted as it streams, so the destination receives plaintext:

```java
byte[] plaintext = store.get(id).decrypt(key).toBytes().get().orElseThrow().getBytes();
```

The request and the object must agree: fetching an encrypted object without `decrypt(key)`, or supplying a key for an object that is not encrypted, fails with `DecryptionException` rather than returning bytes that are not what you asked for. To handle an encrypted object **without** the key — caching, relaying, or copying it to another store — use `raw()`, which yields the stored ciphertext (still integrity-checked) verbatim:

```java
store.get(id).raw().toFile(Path.of("/tmp/blob.enc")).get();
```

> **Encryption defeats deduplication by design.** Each encrypted stream begins with a fresh random header, so identical plaintext produces different ciphertext — and therefore a different content id — on every put. A re-uploaded object is a new object, not a dedup hit, which counts against quota.

### Metadata, listing, existence, deletion

```java
// Metadata only, without downloading the payload
Optional<IonObject> meta = store.getIonObject(id).get();   // empty if not found

// Existence check (HEAD)
boolean present = store.exists(id).get();

// Paginated listing of the authenticated user's objects (1-based page)
PaginatedResult<IonObject> page = store.list(1, 100).get();
for (IonObject o : page.items())
    System.out.println(o.getId());

// Delete a reference owned by the authenticated user
boolean deleted = store.delete(id).get();        // false if it did not exist
```

### Federation

To fetch an object that lives on a different Ion Store node, open the get with `get(peerId, id)`; the bound service fetches and caches it for you. The returned `GetRequest` behaves exactly like the local one — same destinations, same `decrypt(key)`/`raw()`:

```java
Optional<BytesIonObject> obj = store.get(peerId, id).toBytes().get();
store.get(peerId, id).toFile(Path.of("/tmp/out.bin")).get();
```

---

## API Overview

**Entry points** (`put()` opens a `PutRequest`, `get(...)` a `GetRequest`; both are terminated as shown):

| Method | Returns | Auth | Notes |
|---|---|---|---|
| `put()` | `PutRequest` | yes | Fluent builder; terminated by `send()`. |
| `get(Id)` / `get(Id peerId, Id)` | `GetRequest` | no | Fluent builder; terminated by a `to*(...)` destination. |
| `getIonObject(Id)` | `Optional<IonObject>` | no | Metadata only (no payload); empty if absent. |
| `exists(Id)` | `Boolean` | no | HEAD check. |
| `list(long page, long pageSize)` | `PaginatedResult<IonObject>` | yes | The caller's objects, newest first. |
| `delete(Id)` | `Boolean` | yes | `false` if the object did not exist. |
| `close()` | `Void` | — | Releases the HTTP client. |

**`PutRequest`** — configure, then `send()`:

| Method | Notes |
|---|---|
| `content(byte[] / Buffer / Path / InputStream[, closeStream] / ReadStream)` | The payload source (required; a later call replaces an earlier one). |
| `name(String)`, `contentType(String)`, `ttl(long seconds)` | Object description; all optional. |
| `contentLength(long)` | Length hint for the stream sources; ignored by array/buffer/file. |
| `metadata(String, Object)` / `metadata(Map)` | Custom `Ion-*` metadata. |
| `encrypt(byte[] key)` | Client-side encryption with a `SecretStream.KEY_BYTES`-byte key. |
| `send()` → `ContextualFuture<IonObject>` | Uploads and completes with the stored metadata. |

**`GetRequest`** — optionally shape, then choose a destination (the destination is the terminal call):

| Method | Notes |
|---|---|
| `decrypt(byte[] key)` | Decrypt as it streams; mutually exclusive with `raw()`. |
| `raw()` | Take the stored bytes verbatim (ciphertext for encrypted objects), still integrity-checked. |
| `toBytes()` → `Optional<BytesIonObject>` | Into memory, payload included. |
| `toBuffer(Buffer)` → `Optional<IonObject>` | Append payload to a caller buffer; returns metadata only. |
| `toFile(Path)` → `Optional<IonObject>` | To a file; removed on failure. |
| `toOutputStream(OutputStream[, boolean close])` → `Optional<IonObject>` | To a blocking stream; not closed unless requested. |
| `toWriteStream(WriteStream<Buffer>)` → `Optional<IonObject>` | To a Vert.x write stream (ended on completion). |

Accessors: `getUserId()`, `getDeviceId()`, `getServicePeerId()`, `getServiceUrl()`, `isClosed()`.

---

## Integrity

Every payload retrieval is verified: the client hashes the streamed bytes (SHA-256) and compares the result against the content id the service advertises in the `Ion-Content-Id` header. A mismatch — or a missing/malformed header — fails the future with `ObjectIntegrityException`.

- For the **file** sink, the partially written file is removed on failure.
- For an **`OutputStream`/`WriteStream`** sink, the destination cannot be rolled back: corrupt bytes may already have been written before the future fails.
- Because the content id covers the whole object, **ranged downloads are intentionally not offered** — a partial body cannot be verified.

## Error Handling

Failures surface as [`IonStoreException`](src/main/java/io/bosonnetwork/ionstore/exceptions/IonStoreException.java) or one of its category-specific subclasses in the [`exceptions`](src/main/java/io/bosonnetwork/ionstore/exceptions) package, so you can react by catching the specific type:

| Exception | When |
|---|---|
| `UnauthorizedException` | Missing/invalid token (HTTP 401) — fix credentials |
| `ForbiddenException` | Not permitted (HTTP 403) |
| `TtlExceededException` | Requested TTL above the service maximum (HTTP 403) — lower the TTL |
| `InvalidRequestException` | Malformed request / bad id / bad pagination (HTTP 400) |
| `ObjectTooLargeException` | Payload above the service maximum (HTTP 413) — reduce size |
| `QuotaExceededException` | Storage quota exhausted (HTTP 507) — free space or retry later |
| `ObjectNotFoundException` | Object absent (HTTP 404) — *not* thrown by `get`/`exists`/`delete`, which return `null`/`false` |
| `ObjectIntegrityException` | Content-id mismatch on download (or a service-side integrity error, HTTP 422) |
| `DecryptionException` | Client-side only: the get and the object disagree about encryption (encrypted object fetched without a key, or a key supplied for a plain object), or the ciphertext cannot be framed for decryption. Carries no HTTP status. |
| `IonStoreIOException`, `MetabaseException`, `IonStoreServerException` | Server-side faults (HTTP 500) |
| `PeerNotFoundException`, `PeerRequestException`, `PeerResponseException` | Federation faults (HTTP 502) |

Every exception preserves the response's details: `getStatus()` (the HTTP status, or `IonStoreException.NO_HTTP_STATUS` for transport/client-side errors), `getErrorCode()` (the service's stable numeric code, preserved even for an unrecognized category), `getMessage()` (the service message, with any federation peer detail appended), and `getNested()` (the remote peer's status/message for federation failures).

Catch the **specific type** rather than branching on the HTTP status: a single status can map to more than one category — HTTP `403` is returned both for `ForbiddenException` and for `TtlExceededException`. An error category the client does not recognize (e.g. from a newer service) surfaces as a plain `IonStoreException` that still carries the original numeric code.

```java
try {
    store.put().content(bytes).send().get();
} catch (ExecutionException e) {
    if (e.getCause() instanceof QuotaExceededException qe)
        // free space or retry later
    else if (e.getCause() instanceof ObjectTooLargeException te)
        // reduce the payload size
    else if (e.getCause() instanceof TtlExceededException tt)
        // lower the requested TTL
    else if (e.getCause() instanceof UnauthorizedException ue)
        // fix credentials / token
    else if (e.getCause() instanceof IonStoreException ise)
        // ise.getStatus() / ise.getErrorCode() / ise.getMessage()
}
```

---

## Contributing

We welcome contributions from the open-source community. To get started:

1. Fork this repository and create a feature branch.
2. Make your changes and add tests where applicable.
3. Ensure `mvn clean verify` passes.
4. Open a pull request with a clear description of the change.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

---

## License

This project is licensed under the [MIT License](LICENSE).