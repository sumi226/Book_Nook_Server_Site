import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";
import { ObjectId } from "mongodb";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
} from "jose";

const issuer = "https://auth.booknook.test";
const audience = "https://auth.booknook.test";
const signingKeyId = "booknook-test-key";
const { privateKey, publicKey } = await generateKeyPair("EdDSA");
const { privateKey: unrelatedPrivateKey } = await generateKeyPair("EdDSA");
const jwk = {
  ...(await exportJWK(publicKey)),
  kid: signingKeyId,
  alg: "EdDSA",
  use: "sig",
};

process.env.PORT = "8000";
process.env.MONGODB_URI = "mongodb://127.0.0.1/booknook-test";
process.env.DB_NAME = "booknook-test";
process.env.ALLOWED_ORIGIN = "http://localhost:3000";
process.env.BETTER_AUTH_ISSUER = issuer;
process.env.BETTER_AUTH_AUDIENCE = audience;
process.env.BETTER_AUTH_JWKS_URL = `${issuer}/api/auth/jwks`;

const [{ createApp }, { createAuthenticate }] = await Promise.all([
  import("../src/app.js"),
  import("../src/middleware/require-auth.js"),
]);

function objectIdValue(value) {
  return value instanceof ObjectId ? value.toHexString() : value;
}

function matches(document, filter) {
  return Object.entries(filter).every(([key, expected]) => {
    const actual = document[key];
    if (expected && typeof expected === "object" && "$gte" in expected) {
      return actual >= expected.$gte;
    }

    return objectIdValue(actual) === objectIdValue(expected);
  });
}

class FakeCursor {
  constructor(documents) {
    this.documents = documents;
    this.sortFields = {};
    this.offset = 0;
    this.pageSize = Infinity;
  }

  sort(fields) {
    this.sortFields = fields;
    return this;
  }

  skip(offset) {
    this.offset = offset;
    return this;
  }

  limit(pageSize) {
    this.pageSize = pageSize;
    return this;
  }

  async toArray() {
    const results = [...this.documents];
    const sortFields = Object.entries(this.sortFields);

    results.sort((left, right) => {
      for (const [field, direction] of sortFields) {
        const leftValue = objectIdValue(left[field]);
        const rightValue = objectIdValue(right[field]);
        const order =
          leftValue instanceof Date && rightValue instanceof Date
            ? leftValue.getTime() - rightValue.getTime()
            : String(leftValue).localeCompare(String(rightValue));

        if (order !== 0) {
          return order * direction;
        }
      }

      return 0;
    });

    return results.slice(this.offset, this.offset + this.pageSize);
  }
}

class FakeCollection {
  documents = [];

  find(filter) {
    return new FakeCursor(this.documents.filter((document) => matches(document, filter)));
  }

  async findOne(filter) {
    return this.documents.find((document) => matches(document, filter)) ?? null;
  }

  async countDocuments(filter) {
    return this.documents.filter((document) => matches(document, filter)).length;
  }

  async insertOne(document) {
    const insertedId = new ObjectId();
    this.documents.push({ ...document, _id: insertedId });
    return { insertedId };
  }

  async updateOne(filter, update) {
    const document = this.documents.find((entry) => matches(entry, filter));
    if (!document) {
      return { matchedCount: 0, modifiedCount: 0 };
    }

    Object.assign(document, update.$set);
    for (const [field, amount] of Object.entries(update.$inc ?? {})) {
      document[field] += amount;
    }

    return { matchedCount: 1, modifiedCount: 1 };
  }

  async deleteOne(filter) {
    const index = this.documents.findIndex((document) => matches(document, filter));
    if (index < 0) {
      return { deletedCount: 0 };
    }

    this.documents.splice(index, 1);
    return { deletedCount: 1 };
  }
}

const bookCollection = new FakeCollection();
const borrowCollection = new FakeCollection();
const database = {
  collection(name) {
    if (name === "books") return bookCollection;
    if (name === "borrows") return borrowCollection;
    throw new Error(`Unexpected collection: ${name}`);
  },
};
const mongoClient = {
  startSession() {
    return {
      async withTransaction(callback) {
        return callback();
      },
      async endSession() {},
    };
  },
};

const app = createApp({
  authenticateRequest: createAuthenticate({
    keySet: createLocalJWKSet({ keys: [jwk] }),
    issuer,
    audience,
  }),
});
app.locals.database = database;
app.locals.mongoClient = mongoClient;

const apiServer = app.listen(0, "127.0.0.1");
await new Promise((resolve) => apiServer.once("listening", resolve));
const apiAddress = apiServer.address();
const apiUrl = `http://127.0.0.1:${apiAddress.port}`;

after(async () => {
  apiServer.closeAllConnections();
  await new Promise((resolve, reject) =>
    apiServer.close((error) => (error ? reject(error) : resolve())),
  );
});

beforeEach(() => {
  bookCollection.documents = [];
  borrowCollection.documents = [];
});

async function tokenFor({
  userId = "user-1",
  name = "Test Reader",
  email = "reader@example.com",
  tokenIssuer = issuer,
  tokenAudience = audience,
  expiresAt = "2m",
  signingKey = privateKey,
} = {}) {
  return new SignJWT({ name, email })
    .setProtectedHeader({ alg: "EdDSA", kid: signingKeyId })
    .setSubject(userId)
    .setIssuer(tokenIssuer)
    .setAudience(tokenAudience)
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .sign(signingKey);
}

async function request(path, { method = "GET", body, bearer } = {}) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (bearer) headers.authorization = `Bearer ${bearer}`;

  return fetch(`${apiUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function makeBook(overrides = {}) {
  return {
    _id: new ObjectId(),
    title: "Test Book",
    author: "Test Author",
    category: "Fiction",
    image: "https://example.com/book.jpg",
    description: "A test book.",
    addedByName: "Test Reader",
    addedByEmail: "reader@example.com",
    ownerId: "user-1",
    totalCopies: 2,
    availableCopies: 2,
    addedAt: new Date("2026-01-01T00:00:00.000Z"),
    ...overrides,
  };
}

test("GET /books is public, paginated, and sorted newest first", async () => {
  bookCollection.documents = [
    makeBook({ title: "Oldest", addedAt: new Date("2025-01-01T00:00:00.000Z") }),
    makeBook({ title: "Newest", addedAt: new Date("2026-03-01T00:00:00.000Z") }),
    makeBook({ title: "Middle", addedAt: new Date("2026-02-01T00:00:00.000Z") }),
  ];

  const response = await request("/books?page=1&limit=2");
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(result.books.map((book) => book.title), ["Newest", "Middle"]);
  assert.deepEqual(result.pagination, {
    page: 1,
    limit: 2,
    total: 3,
    totalPages: 2,
  });
  assert.equal((await request("/books/")).status, 200);

  const invalidPage = await request("/books?page=0");
  assert.equal(invalidPage.status, 400);
});

test("GET /books/:id returns a book and validates IDs", async () => {
  const book = makeBook();
  bookCollection.documents.push(book);

  const response = await request(`/books/${book._id.toHexString()}`);
  const result = await response.json();
  assert.equal(response.status, 200);
  assert.equal(result.book.title, book.title);

  assert.equal((await request("/books/not-an-object-id")).status, 400);
  assert.equal((await request(`/books/${new ObjectId().toHexString()}`)).status, 404);
});

test("POST /books requires a valid JWT and derives owner fields from its claims", async () => {
  const body = {
    title: "New Book",
    author: "Book Author",
    category: "Science",
    image: "https://example.com/new-book.jpg",
    description: "A newly added book.",
    totalCopies: 3,
  };

  assert.equal((await request("/books", { method: "POST", body })).status, 401);
  assert.equal(
    (
      await request("/books", {
        method: "POST",
        body,
        bearer: "invalid.token.value",
      })
    ).status,
    401,
  );

  for (const claims of [
    { tokenIssuer: "https://wrong-issuer.example" },
    { tokenAudience: "https://wrong-audience.example" },
    { expiresAt: 946684800 },
    { signingKey: unrelatedPrivateKey },
  ]) {
    const invalidToken = await tokenFor(claims);
    const invalidResponse = await request("/books", {
      method: "POST",
      bearer: invalidToken,
      body,
    });
    assert.equal(invalidResponse.status, 401);
  }

  const missingIdentity = await tokenFor({ email: null });
  const missingIdentityResponse = await request("/books", {
    method: "POST",
    bearer: missingIdentity,
    body,
  });
  assert.equal(missingIdentityResponse.status, 401);

  const bearer = await tokenFor();
  const invalid = await request("/books", {
    method: "POST",
    bearer,
    body: { ...body, category: "Mystery" },
  });
  assert.equal(invalid.status, 400);

  const spoofedOwner = await request("/books", {
    method: "POST",
    bearer,
    body: { ...body, ownerId: "another-user" },
  });
  assert.equal(spoofedOwner.status, 400);

  const response = await request("/books", { method: "POST", bearer, body });
  const result = await response.json();
  assert.equal(response.status, 201);
  assert.equal(result.book.addedByName, "Test Reader");
  assert.equal(result.book.addedByEmail, "reader@example.com");
  assert.equal(result.book.ownerId, "user-1");
  assert.equal(result.book.availableCopies, 3);
  assert.ok(result.book.addedAt);
});

test("PATCH /books/:id validates input, enforces ownership, and adjusts copies safely", async () => {
  const book = makeBook({ totalCopies: 3, availableCopies: 2 });
  bookCollection.documents.push(book);
  const ownerToken = await tokenFor();
  const otherUserToken = await tokenFor({ userId: "user-2", email: "other@example.com" });

  const notOwner = await request(`/books/${book._id}`, {
    method: "PATCH",
    bearer: otherUserToken,
    body: { title: "Not yours" },
  });
  assert.equal(notOwner.status, 404);

  const updated = await request(`/books/${book._id}`, {
    method: "PATCH",
    bearer: ownerToken,
    body: { title: "Updated Title", totalCopies: 4 },
  });
  const result = await updated.json();
  assert.equal(updated.status, 200);
  assert.equal(result.book.title, "Updated Title");
  assert.equal(result.book.totalCopies, 4);
  assert.equal(result.book.availableCopies, 3);

  const borrowedBook = makeBook({ totalCopies: 2, availableCopies: 0 });
  bookCollection.documents.push(borrowedBook);
  const conflict = await request(`/books/${borrowedBook._id}`, {
    method: "PATCH",
    bearer: ownerToken,
    body: { totalCopies: 1 },
  });
  assert.equal(conflict.status, 409);

  const invalid = await request(`/books/${book._id}`, {
    method: "PATCH",
    bearer: ownerToken,
    body: { availableCopies: 100 },
  });
  assert.equal(invalid.status, 400);
});

test("DELETE /books/:id enforces ownership and rejects active borrows", async () => {
  const book = makeBook();
  bookCollection.documents.push(book);
  const ownerToken = await tokenFor();
  const otherUserToken = await tokenFor({ userId: "user-2", email: "other@example.com" });

  const notOwner = await request(`/books/${book._id}`, {
    method: "DELETE",
    bearer: otherUserToken,
  });
  assert.equal(notOwner.status, 404);

  borrowCollection.documents.push({ bookId: book._id, userEmail: "reader@example.com" });
  const activeBorrow = await request(`/books/${book._id}`, {
    method: "DELETE",
    bearer: ownerToken,
  });
  assert.equal(activeBorrow.status, 409);
  assert.equal(bookCollection.documents.length, 1);

  borrowCollection.documents = [];
  const deleted = await request(`/books/${book._id}`, {
    method: "DELETE",
    bearer: ownerToken,
  });
  assert.equal(deleted.status, 204);
  assert.equal(bookCollection.documents.length, 0);
});
