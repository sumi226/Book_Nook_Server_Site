import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
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

const { createApp, createAuthenticate } = await import("../index.js");

function objectIdValue(value) {
  return value instanceof ObjectId ? value.toHexString() : value;
}

function matches(document, filter) {
  if (filter.$or && Array.isArray(filter.$or)) {
    return filter.$or.some((subFilter) => matches(document, subFilter));
  }

  return Object.entries(filter).every(([key, expected]) => {
    if (key === "$or") return true;
    const actual = document[key];
    if (expected && typeof expected === "object" && !(expected instanceof ObjectId)) {
      if ("$gte" in expected && !(actual >= expected.$gte)) return false;
      if ("$gt" in expected && !(actual > expected.$gt)) return false;
      if ("$lt" in expected && !(actual < expected.$lt)) return false;
      return true;
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

  find(filter = {}) {
    return new FakeCursor(this.documents.filter((document) => matches(document, filter)));
  }

  async findOne(filter) {
    return this.documents.find((document) => matches(document, filter)) ?? null;
  }

  async countDocuments(filter = {}) {
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

    if (update.$set) {
      Object.assign(document, update.$set);
    }
    for (const [field, amount] of Object.entries(update.$inc ?? {})) {
      document[field] = (document[field] ?? 0) + amount;
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
        return await callback();
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
  const jwt = new SignJWT({ name, email })
    .setProtectedHeader({ alg: "EdDSA", kid: signingKeyId })
    .setSubject(userId);

  if (tokenIssuer) jwt.setIssuer(tokenIssuer);
  if (tokenAudience) jwt.setAudience(tokenAudience);
  jwt.setIssuedAt();
  if (expiresAt) jwt.setExpirationTime(expiresAt);

  return jwt.sign(signingKey);
}

async function request(path, { method = "GET", body, bearer } = {}) {
  const headers = new Headers();
  if (body) headers.set("content-type", "application/json");
  if (bearer) headers.set("authorization", `Bearer ${bearer}`);

  const nodeReq = {
    method,
    url: path,
    headers: Object.fromEntries(headers.entries()),
    rawHeaders: [],
    get(name) {
      return headers.get(name.toLowerCase()) || undefined;
    },
    body: body || {},
  };

  return new Promise((resolvePromise) => {
    let statusCode = 200;
    const responseHeaders = new Headers();
    let bodyText = "";

    const nodeRes = {
      statusCode: 200,
      headersSent: false,
      status(code) {
        statusCode = code;
        this.statusCode = code;
        return this;
      },
      set(name, val) {
        responseHeaders.set(name, val);
        return this;
      },
      setHeader(name, val) {
        responseHeaders.set(name, val);
        return this;
      },
      getHeader(name) {
        return responseHeaders.get(name);
      },
      json(payload) {
        this.headersSent = true;
        bodyText = JSON.stringify(payload);
        resolvePromise({
          status: statusCode,
          headers: responseHeaders,
          json: async () => payload,
          text: async () => bodyText,
        });
        return this;
      },
      send(data) {
        this.headersSent = true;
        bodyText = String(data);
        resolvePromise({
          status: statusCode,
          headers: responseHeaders,
          json: async () => JSON.parse(bodyText),
          text: async () => bodyText,
        });
        return this;
      },
      end() {
        this.headersSent = true;
        resolvePromise({
          status: statusCode,
          headers: responseHeaders,
          json: async () => ({}),
          text: async () => "",
        });
        return this;
      },
    };

    app.handle(nodeReq, nodeRes);
  });
}

function makeBook(overrides = {}) {
  const total = overrides.totalCopies ?? 5;
  const available = overrides.availableCopies ?? total;
  return {
    _id: new ObjectId(),
    title: "Default Title",
    author: "Default Author",
    category: "Fiction",
    image: "https://example.com/cover.jpg",
    description: "Default description text.",
    totalCopies: total,
    availableCopies: available,
    copies: available,
    ownerId: "owner-1",
    addedByName: "Default Owner",
    addedByEmail: "owner@example.com",
    addedAt: new Date(),
    ...overrides,
  };
}

// ------------------- JWT VALIDATION TESTS -------------------
test("JWT: protected APIs require valid Bearer token and reject unauthorized calls", async () => {
  // Public routes do not require JWT
  const publicBooks = await request("/books");
  assert.equal(publicBooks.status, 200);

  // Missing bearer token on protected routes returns 401
  assert.equal((await request("/books/mine")).status, 401);
  assert.equal((await request("/books", { method: "POST", body: { title: "X" } })).status, 401);
  assert.equal((await request("/borrows")).status, 401);
  assert.equal((await request("/borrows", { method: "POST", body: { bookId: new ObjectId().toHexString() } })).status, 401);

  // Invalid / forged bearer token returns 401
  const forgedToken = await tokenFor({ signingKey: unrelatedPrivateKey });
  assert.equal((await request("/books/mine", { bearer: forgedToken })).status, 401);

  // Expired bearer token returns 401
  const expiredToken = await tokenFor({ expiresAt: "-10s" });
  assert.equal((await request("/books/mine", { bearer: expiredToken })).status, 401);

  // Wrong issuer returns 401
  const wrongIssuerToken = await tokenFor({ tokenIssuer: "https://unknown.issuer" });
  assert.equal((await request("/books/mine", { bearer: wrongIssuerToken })).status, 401);

  // Valid bearer token returns 200
  const validToken = await tokenFor();
  const validResponse = await request("/books/mine", { bearer: validToken });
  assert.equal(validResponse.status, 200);
});

// ------------------- AVAILABLE COPIES TESTS -------------------
test("Available Copies: Add Book initializes Total Copies, Available Copies, and copies", async () => {
  const token = await tokenFor({ userId: "author-1", name: "Author", email: "author@test.com" });
  const bookData = {
    title: "Clean Code",
    author: "Robert C. Martin",
    category: "Science",
    image: "https://example.com/cleancode.jpg",
    description: "A handbook of agile software craftsmanship.",
    totalCopies: 10,
  };

  const response = await request("/books", {
    method: "POST",
    bearer: token,
    body: bookData,
  });

  assert.equal(response.status, 201);
  const { book } = await response.json();
  assert.equal(book.totalCopies, 10);
  assert.equal(book.availableCopies, 10);
  assert.equal(book.copies, 10);
});

test("Available Copies: Borrowing decrements copies by 1 with $inc", async () => {
  const book = makeBook({ totalCopies: 5, availableCopies: 5, copies: 5 });
  bookCollection.documents.push(book);

  const token = await tokenFor({ userId: "reader-1", email: "reader1@test.com" });
  const borrowRes = await request("/borrows", {
    method: "POST",
    bearer: token,
    body: { bookId: book._id.toHexString() },
  });

  assert.equal(borrowRes.status, 201);
  assert.equal(book.availableCopies, 4);
  assert.equal(book.copies, 4);
});

test("Available Copies: Returning increments copies by 1 with $inc", async () => {
  const book = makeBook({ totalCopies: 5, availableCopies: 4, copies: 4 });
  bookCollection.documents.push(book);

  const token = await tokenFor({ userId: "reader-1", email: "reader1@test.com" });
  const borrowId = new ObjectId();
  borrowCollection.documents.push({
    _id: borrowId,
    bookId: book._id,
    userId: "reader-1",
    userEmail: "reader1@test.com",
    bookTitle: book.title,
    borrowedAt: new Date(),
  });

  const returnRes = await request(`/borrows/${borrowId.toHexString()}`, {
    method: "DELETE",
    bearer: token,
  });

  assert.equal(returnRes.status, 204);
  assert.equal(book.availableCopies, 5);
  assert.equal(book.copies, 5);
  assert.equal(borrowCollection.documents.length, 0);
});

test("Available Copies: When copies are 0, borrowing is rejected with 409", async () => {
  const book = makeBook({ totalCopies: 1, availableCopies: 0, copies: 0 });
  bookCollection.documents.push(book);

  const token = await tokenFor({ userId: "reader-2", email: "reader2@test.com" });
  const response = await request("/borrows", {
    method: "POST",
    bearer: token,
    body: { bookId: book._id.toHexString() },
  });

  assert.equal(response.status, 409);
  const errorData = await response.json();
  assert.match(errorData.error, /No copies of this book are currently available/i);
});

// ------------------- NO DOUBLE BORROW TESTS -------------------
test("No Double Borrow: A user cannot borrow the same book two times simultaneously", async () => {
  const book = makeBook({ totalCopies: 10, availableCopies: 10, copies: 10 });
  bookCollection.documents.push(book);

  const token = await tokenFor({ userId: "same-user", email: "same@test.com" });

  // First borrow succeeds
  const first = await request("/borrows", {
    method: "POST",
    bearer: token,
    body: { bookId: book._id.toHexString() },
  });
  assert.equal(first.status, 201);
  assert.equal(book.availableCopies, 9);

  // Second borrow of the same book fails with 409 conflict
  const second = await request("/borrows", {
    method: "POST",
    bearer: token,
    body: { bookId: book._id.toHexString() },
  });
  assert.equal(second.status, 409);
  const secondError = await second.json();
  assert.equal(secondError.error, "You have already borrowed this book.");
  assert.equal(book.availableCopies, 9); // Stock is unchanged
});

test("No Double Borrow: User can borrow again AFTER returning the book", async () => {
  const book = makeBook({ totalCopies: 5, availableCopies: 5, copies: 5 });
  bookCollection.documents.push(book);

  const token = await tokenFor({ userId: "returner", email: "returner@test.com" });

  // Borrow
  const first = await request("/borrows", {
    method: "POST",
    bearer: token,
    body: { bookId: book._id.toHexString() },
  });
  assert.equal(first.status, 201);
  const { borrow } = await first.json();

  // Return
  const returned = await request(`/borrows/${borrow._id}`, {
    method: "DELETE",
    bearer: token,
  });
  assert.equal(returned.status, 204);
  assert.equal(book.availableCopies, 5);

  // Can borrow again now that it was returned
  const second = await request("/borrows", {
    method: "POST",
    bearer: token,
    body: { bookId: book._id.toHexString() },
  });
  assert.equal(second.status, 201);
  assert.equal(book.availableCopies, 4);
});

