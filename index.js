import "dotenv/config";
import cors from "cors";
import express from "express";
import multer from "multer";
import { MongoClient, ObjectId } from "mongodb";
import { createLocalJWKSet, createRemoteJWKSet, errors, jwtVerify } from "jose";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function requiredEnvironmentVariable(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable ${name}.`);
  }
  return value;
}

const port = Number(process.env.PORT?.trim() || "8000");
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}

const defaultClientUrl =
  process.env.NODE_ENV === "production"
    ? "https://booknookclientsite.vercel.app"
    : "http://localhost:3000";
const clientUrl = (
  process.env.CLIENT_URL?.trim() || defaultClientUrl
).replace(/\/+$/, "");
const authBaseUrl = (
  process.env.BETTER_AUTH_URL?.trim() || clientUrl
).replace(/\/+$/, "");
const mongodbUri = requiredEnvironmentVariable("MONGODB_URI");
const dbName = process.env.DB_NAME?.trim() || "booknook";
const allowedOrigin = (
  process.env.ALLOWED_ORIGIN?.trim() || clientUrl
).replace(/\/+$/, "");
const authIssuer = process.env.BETTER_AUTH_ISSUER?.trim() || authBaseUrl;
const authAudience = process.env.BETTER_AUTH_AUDIENCE?.trim() || authBaseUrl;
const jwksUrl = process.env.BETTER_AUTH_JWKS_URL?.trim() ||
  `${authBaseUrl}/api/auth/jwks`;

try {
  const parsedJwksUrl = new URL(jwksUrl);
  if (!["http:", "https:"].includes(parsedJwksUrl.protocol)) {
    throw new Error();
  }
} catch {
  throw new Error("BETTER_AUTH_JWKS_URL must be an absolute HTTP or HTTPS URL.");
}

const mongoClient = new MongoClient(mongodbUri);
const jwks = createRemoteJWKSet(new URL(jwksUrl));
const categories = new Set(["Fiction", "Science", "History", "Kids", "Others"]);
const editableBookFields = new Set([
  "title",
  "author",
  "category",
  "image",
  "description",
  "totalCopies",
]);
const stringLimits = {
  title: 200,
  author: 120,
  image: 2048,
  description: 5000,
};
const allowedImageTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024, files: 1 },
  fileFilter(request, file, callback) {
    if (!allowedImageTypes.has(file.mimetype)) {
      callback(new HttpError(400, "Cover must be a JPEG, PNG, WebP, or GIF image."));
      return;
    }
    callback(null, true);
  },
});

export class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.details = details;
  }
}

export function createAuthenticate({ keySet = jwks, issuer = authIssuer, audience = authAudience } = {}) {
  const allowedIssuers = Array.isArray(issuer)
    ? issuer
    : [issuer, authBaseUrl, "http://localhost:3000", "http://127.0.0.1:3000", "https://booknookclientsite.vercel.app"].filter(Boolean);
  const allowedAudiences = Array.isArray(audience)
    ? audience
    : [audience, authBaseUrl, "http://localhost:3000", "http://127.0.0.1:3000", "https://booknookclientsite.vercel.app"].filter(Boolean);

  return async function authenticateRequest(request, response, next) {
    const match = request.get("authorization")?.match(/^Bearer\s+(\S+)$/i);
    if (!match) {
      return response.status(401).json({ error: "A bearer token is required." });
    }

    const token = match[1];
    let payload;
    let authError;

    try {
      ({ payload } = await jwtVerify(token, keySet, {
        issuer: allowedIssuers,
        audience: allowedAudiences,
      }));
    } catch (error) {
      authError = error;
    }

    // Fallback if remote JWKS endpoint is unreachable: verify using public keys stored in MongoDB jwks collection
    if (!payload && request.app?.locals?.database) {
      try {
        const dbJwks = await request.app.locals.database.collection("jwks").find({}).toArray();
        if (dbJwks && dbJwks.length > 0) {
          const keys = dbJwks.map((k) => {
            const parsed = typeof k.publicKey === "string" ? JSON.parse(k.publicKey) : (k.publicKey || {});
            return {
              alg: k.alg || "EdDSA",
              crv: k.crv,
              ...parsed,
              kid: k.id || k._id?.toString(),
            };
          });
          const localKeySet = createLocalJWKSet({ keys });
          ({ payload } = await jwtVerify(token, localKeySet, {
            issuer: allowedIssuers,
            audience: allowedAudiences,
          }));
          authError = null;
        }
      } catch {
        // preserve authError
      }
    }

    if (!payload) {
      if (
        authError instanceof errors.JWKSTimeout ||
        authError instanceof TypeError ||
        (authError instanceof errors.JOSEError && authError.constructor === errors.JOSEError)
      ) {
        return response
          .status(503)
          .json({ error: "The Better Auth JWKS service is unavailable or misconfigured." });
      }
      if (authError instanceof errors.JOSEError) {
        return response.status(401).json({ error: "The bearer token is invalid or expired." });
      }
      return next(authError);
    }

    const userId = payload.sub || payload.id || payload.userId || payload.user?.id;
    const name = payload.name || payload.user?.name || (payload.email ? payload.email.split("@")[0] : "");
    const email = payload.email || payload.user?.email || "";

    if (
      typeof userId !== "string" ||
      !userId.trim() ||
      typeof name !== "string" ||
      !name.trim() ||
      typeof email !== "string" ||
      !email.trim()
    ) {
      return response
        .status(401)
        .json({ error: "The bearer token is missing user identity claims." });
    }

    request.auth = {
      userId: userId.trim(),
      name: name.trim(),
      email: email.trim().toLowerCase(),
    };
    return next();
  };
}

function parseObjectId(value, label) {
  if (typeof value !== "string" || !/^[\da-f]{24}$/i.test(value)) {
    throw new HttpError(400, `${label} must be a valid MongoDB ObjectId.`);
  }
  return new ObjectId(value);
}

function parsePositiveInteger(value, name, fallback, maximum) {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
    throw new HttpError(400, `${name} must be a positive integer.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new HttpError(400, `${name} must not exceed ${maximum}.`);
  }
  return parsed;
}

function pagination(request) {
  const page = parsePositiveInteger(request.query.page, "page", 1, Number.MAX_SAFE_INTEGER);
  const limit = parsePositiveInteger(request.query.limit, "limit", 12, 100);
  const skip = (page - 1) * limit;
  if (!Number.isSafeInteger(skip)) {
    throw new HttpError(400, "Requested page is too large.");
  }
  return { page, limit, skip };
}

function validateBookInput(body, { partial = false } = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Request body must be a JSON object.");
  }

  const unknownFields = Object.keys(body).filter((field) => !editableBookFields.has(field));
  if (unknownFields.length) {
    throw new HttpError(400, "Request contains unsupported book fields.", unknownFields);
  }

  const fields = Object.keys(body);
  if (!fields.length) {
    throw new HttpError(
      400,
      partial ? "At least one book field is required." : "Book fields are required.",
    );
  }

  const clean = {};
  const issues = [];
  for (const field of ["title", "author", "category", "image", "description"]) {
    if (!Object.hasOwn(body, field)) {
      if (!partial) issues.push(`${field} is required.`);
      continue;
    }
    if (typeof body[field] !== "string" || !body[field].trim()) {
      issues.push(`${field} must be a non-empty string.`);
      continue;
    }

    const value = body[field].trim();
    if (stringLimits[field] && value.length > stringLimits[field]) {
      issues.push(`${field} must be at most ${stringLimits[field]} characters.`);
      continue;
    }
    if (field === "category" && !categories.has(value)) {
      issues.push(`category must be one of: ${[...categories].join(", ")}.`);
      continue;
    }
    if (field === "image") {
      try {
        const imageUrl = new URL(value);
        if (!["http:", "https:"].includes(imageUrl.protocol)) {
          issues.push("image must be an HTTP or HTTPS URL.");
          continue;
        }
      } catch {
        issues.push("image must be a valid HTTP or HTTPS URL.");
        continue;
      }
    }
    clean[field] = value;
  }

  if (Object.hasOwn(body, "totalCopies")) {
    if (!Number.isInteger(body.totalCopies) || body.totalCopies < 1 || body.totalCopies > 100000) {
      issues.push("totalCopies must be an integer between 1 and 100000.");
    } else {
      clean.totalCopies = body.totalCopies;
    }
  } else if (!partial) {
    issues.push("totalCopies is required.");
  }

  if (issues.length) {
    throw new HttpError(400, "Book validation failed.", issues);
  }
  return clean;
}

function getDatabase(request) {
  const database = request.app.locals.database;
  const client = request.app.locals.mongoClient;
  if (!database || !client) {
    throw new Error("MongoDB has not been attached to the Express application.");
  }
  return { database, client };
}

async function executeTransaction(client, action) {
  if (!client || typeof client.startSession !== "function") {
    return action(null);
  }
  let session;
  try {
    session = client.startSession();
  } catch {
    return action(null);
  }
  try {
    let result;
    try {
      await session.withTransaction(async () => {
        result = await action(session);
      });
      return result;
    } catch (error) {
      if (
        error?.message?.includes("Transaction numbers are only allowed") ||
        error?.message?.includes("replica set member") ||
        error?.codeName === "IllegalOperation"
      ) {
        return await action(null);
      }
      throw error;
    }
  } finally {
    try {
      await session.endSession();
    } catch {}
  }
}

function errorHandler(error, request, response, next) {
  if (response.headersSent) return next(error);
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return response.status(413).json({ error: "Cover image must be 4 MB or smaller." });
    }
    return response.status(400).json({ error: "Upload one image file using the image field." });
  }
  if (error.type === "entity.parse.failed") {
    return response.status(400).json({ error: "Request body must be valid JSON." });
  }
  if (error.type === "entity.too.large") {
    return response.status(413).json({ error: "Request body is too large." });
  }
  if (error.code === 11000) {
    return response.status(409).json({ error: "You have already borrowed this book." });
  }

  const status = Number.isInteger(error.status) ? error.status : 500;
  if (status >= 500) {
    console.error("API request failed.", error);
    if (error instanceof HttpError) {
      return response.status(status).json({ error: error.message });
    }
    return response.status(500).json({ error: "An unexpected server error occurred." });
  }

  const payload = { error: error.message };
  if (error.details) payload.details = error.details;
  return response.status(status).json(payload);
}

export function createApp({ authenticateRequest = createAuthenticate() } = {}) {
  const app = express();
  const allowedOrigins = [
    clientUrl,
    allowedOrigin,
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://booknookclientsite.vercel.app",
  ].filter(Boolean);

  app.use(
    cors({
      origin: (origin, callback) => {
        if (
          !origin ||
          allowedOrigins.includes(origin) ||
          allowedOrigins.includes(origin.replace(/\/+$/, "")) ||
          /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)
        ) {
          return callback(null, true);
        }
        return callback(null, true);
      },
      credentials: true,
    }),
  );
  app.use(express.json({ limit: "1mb" }));

  // POST /images — authenticated ImgBB upload; MongoDB stores the returned URL with the book.
  app.post(
    "/images",
    authenticateRequest,
    (request, response, next) => {
      imageUpload.single("image")(request, response, next);
    },
    async (request, response) => {
      if (!request.file) {
        throw new HttpError(400, "Choose a cover image to upload.");
      }

      const apiKey = process.env.IMGBB_API_KEY?.trim();
      if (!apiKey) {
        throw new HttpError(
          503,
          "Image upload is not configured. Set IMGBB_API_KEY on the API server.",
        );
      }

      const formData = new FormData();
      formData.set("key", apiKey);
      formData.set(
        "image",
        new Blob([request.file.buffer], { type: request.file.mimetype }),
        request.file.originalname,
      );

      const uploadResponse = await fetch("https://api.imgbb.com/1/upload", {
        method: "POST",
        body: formData,
      });
      const result = await uploadResponse.json().catch(() => null);
      const url = result?.data?.display_url || result?.data?.url;
      if (!uploadResponse.ok || result?.success !== true || typeof url !== "string") {
        throw new HttpError(
          502,
          result?.error?.message || "ImgBB could not upload this cover image.",
        );
      }

      return response.status(201).json({ url });
    },
  );

  // GET /books — public, paginated list of books.
  app.get("/books", async (request, response) => {
    const { page, limit, skip } = pagination(request);
    const { database } = getDatabase(request);
    const books = database.collection("books");
    const [items, total] = await Promise.all([
      books.find({}).sort({ addedAt: -1, _id: -1 }).skip(skip).limit(limit).toArray(),
      books.countDocuments({}),
    ]);
    return response.json({
      books: items,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    });
  });

  // GET /books/mine — authenticated user's books.
  app.get("/books/mine", authenticateRequest, async (request, response) => {
    const { page, limit, skip } = pagination(request);
    const { database } = getDatabase(request);
    const books = database.collection("books");
    const filter = {
      $or: [
        { ownerId: request.auth.userId },
        { addedByEmail: request.auth.email },
      ],
    };
    const [items, total] = await Promise.all([
      books.find(filter).sort({ addedAt: -1, _id: -1 }).skip(skip).limit(limit).toArray(),
      books.countDocuments(filter),
    ]);
    return response.json({
      books: items,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    });
  });

  // GET /books/:id — public, single book.
  app.get("/books/:id", async (request, response) => {
    const id = parseObjectId(request.params.id, "Book ID");
    const book = await getDatabase(request).database.collection("books").findOne({ _id: id });
    if (!book) throw new HttpError(404, "Book not found.");
    return response.json({ book });
  });

  // POST /books — authenticated book creation.
  app.post("/books", authenticateRequest, async (request, response) => {
    const input = validateBookInput(request.body);
    const now = new Date();
    const book = {
      ...input,
      addedByName: request.auth.name,
      addedByEmail: request.auth.email,
      ownerId: request.auth.userId,
      totalCopies: input.totalCopies,
      availableCopies: input.totalCopies,
      copies: input.totalCopies,
      addedAt: now,
    };
    const result = await getDatabase(request).database.collection("books").insertOne(book);
    return response.status(201).json({ book: { ...book, _id: result.insertedId } });
  });

  // PATCH /books/:id — authenticated owner-only book update.
  app.patch("/books/:id", authenticateRequest, async (request, response) => {
    const id = parseObjectId(request.params.id, "Book ID");
    const input = validateBookInput(request.body, { partial: true });
    const books = getDatabase(request).database.collection("books");
    const filter = {
      _id: id,
      $or: [
        { ownerId: request.auth.userId },
        { addedByEmail: request.auth.email },
      ],
    };
    const existing = await books.findOne(filter);
    if (!existing) throw new HttpError(404, "Book not found.");

    const update = { $set: input };
    if (Object.hasOwn(input, "totalCopies")) {
      const difference = input.totalCopies - existing.totalCopies;
      filter.totalCopies = existing.totalCopies;
      if (difference < 0) {
        filter.availableCopies = { $gte: -difference };
      }
      if (difference !== 0) {
        update.$inc = {
          availableCopies: difference,
          ...(typeof existing.copies === "number" ? { copies: difference } : {}),
        };
      }
    }

    const result = await books.updateOne(filter, update);
    if (!result.matchedCount) {
      const latest = await books.findOne({ _id: id });
      if (!latest) throw new HttpError(404, "Book not found.");
      throw new HttpError(
        409,
        latest.availableCopies < latest.totalCopies - input.totalCopies
          ? "Total copies cannot be lower than the number of copies currently borrowed."
          : "The book changed during this update. Please reload and try again.",
      );
    }

    const book = await books.findOne({ _id: id });
    if (!book) throw new HttpError(404, "Book not found.");
    return response.json({ book });
  });

  // DELETE /books/:id — authenticated owner-only deletion without active borrows.
  app.delete("/books/:id", authenticateRequest, async (request, response) => {
    const id = parseObjectId(request.params.id, "Book ID");
    const { database, client } = getDatabase(request);
    await executeTransaction(client, async (session) => {
      const opts = session ? { session } : undefined;
      const books = database.collection("books");
      const book = await books.findOne(
        {
          _id: id,
          $or: [
            { ownerId: request.auth.userId },
            { addedByEmail: request.auth.email },
          ],
        },
        opts,
      );
      if (!book) throw new HttpError(404, "Book not found.");

      const activeBorrows = await database
        .collection("borrows")
        .countDocuments({ bookId: id }, opts);
      if (activeBorrows > 0) {
        throw new HttpError(409, "A book with active borrows cannot be deleted.");
      }

      const result = await books.deleteOne(
        { _id: id },
        opts,
      );
      if (result.deletedCount !== 1) {
        throw new HttpError(409, "The book changed during deletion. Please try again.");
      }
    });
    return response.status(204).end();
  });

  // POST /borrows — authenticated borrow with transactional stock update.
  app.post("/borrows", authenticateRequest, async (request, response) => {
    if (
      !request.body ||
      typeof request.body !== "object" ||
      Array.isArray(request.body) ||
      !Object.hasOwn(request.body, "bookId") ||
      Object.keys(request.body).some((field) => !["bookId", "durationDays"].includes(field))
    ) {
      throw new HttpError(400, "Request body must contain bookId and may contain durationDays.");
    }

    const bookId = parseObjectId(request.body.bookId, "bookId");
    const durationDays = request.body.durationDays ?? 7;
    if (!Number.isInteger(durationDays) || durationDays < 1 || durationDays > 30) {
      throw new HttpError(400, "durationDays must be an integer between 1 and 30.");
    }

    const { database, client } = getDatabase(request);
    const books = database.collection("books");
    const borrows = database.collection("borrows");

    const borrow = await executeTransaction(client, async (session) => {
      const opts = session ? { session } : undefined;

      // No double borrow: user cannot borrow the same book two times simultaneously
      const existing = await borrows.findOne(
        {
          bookId,
          $or: [
            { userId: request.auth.userId },
            { userEmail: request.auth.email },
          ],
        },
        opts,
      );
      if (existing) {
        throw new HttpError(409, "You have already borrowed this book.");
      }

      const book = await books.findOne({ _id: bookId }, opts);
      if (!book) throw new HttpError(404, "Book not found.");

      const available =
        typeof book.availableCopies === "number"
          ? book.availableCopies
          : (typeof book.copies === "number" ? book.copies : 0);

      if (available <= 0) {
        throw new HttpError(409, "No copies of this book are currently available.");
      }

      const incUpdate = { availableCopies: -1 };
      if (typeof book.copies === "number") {
        incUpdate.copies = -1;
      }

      const stockUpdate = await books.updateOne(
        {
          _id: bookId,
          $or: [
            { availableCopies: { $gt: 0 } },
            { copies: { $gt: 0 } },
          ],
        },
        { $inc: incUpdate },
        opts,
      );
      if (!stockUpdate.matchedCount) {
        throw new HttpError(409, "No copies of this book are currently available.");
      }

      const newBorrow = {
        bookId,
        bookTitle: book.title,
        userId: request.auth.userId,
        userName: request.auth.name,
        userEmail: request.auth.email,
        borrowedAt: new Date(),
        dueAt: new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000),
      };

      const result = await borrows.insertOne(newBorrow, opts);
      newBorrow._id = result.insertedId;
      return newBorrow;
    });

    return response.status(201).json({ borrow });
  });

  // GET /borrows — authenticated user's borrow history.
  app.get("/borrows", authenticateRequest, async (request, response) => {
    const { page, limit, skip } = pagination(request);
    const { database } = getDatabase(request);
    const borrows = database.collection("borrows");
    const filter = {
      $or: [
        { userId: request.auth.userId },
        { userEmail: request.auth.email },
      ],
    };
    const [items, total] = await Promise.all([
      borrows
        .find(filter)
        .sort({ borrowedAt: -1, _id: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      borrows.countDocuments(filter),
    ]);
    return response.json({
      borrows: items,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    });
  });

  // DELETE /borrows/:id — authenticated user returns their own borrowed book.
  app.delete("/borrows/:id", authenticateRequest, async (request, response) => {
    const borrowId = parseObjectId(request.params.id, "Borrow ID");
    const { database, client } = getDatabase(request);
    const books = database.collection("books");
    const borrows = database.collection("borrows");

    await executeTransaction(client, async (session) => {
      const opts = session ? { session } : undefined;

      const borrow = await borrows.findOne(
        {
          _id: borrowId,
          $or: [
            { userId: request.auth.userId },
            { userEmail: request.auth.email },
          ],
        },
        opts,
      );
      if (!borrow) throw new HttpError(404, "Borrow record not found.");

      const book = await books.findOne({ _id: borrow.bookId }, opts);
      if (book) {
        const maxCopies = book.totalCopies ?? Infinity;
        const currentCopies =
          typeof book.availableCopies === "number"
            ? book.availableCopies
            : (book.copies ?? 0);

        if (currentCopies < maxCopies) {
          const incUpdate = { availableCopies: 1 };
          if (typeof book.copies === "number") {
            incUpdate.copies = 1;
          }
          await books.updateOne(
            { _id: borrow.bookId },
            { $inc: incUpdate },
            opts,
          );
        }
      }

      const removal = await borrows.deleteOne(
        { _id: borrowId },
        opts,
      );
      if (!removal.deletedCount) {
        throw new HttpError(409, "The borrow record changed. Please try again.");
      }
    });

    return response.status(204).end();
  });

  app.use(errorHandler);
  return app;
}

const app = createApp();
export default async function handler(request, response) {
  try {
    if (!app.locals.database) {
      const { database } = await connectToDatabase();
      app.locals.database = database;
      app.locals.mongoClient = mongoClient;
    }
    return app(request, response);
  } catch (error) {
    console.error("API database connection failed.", error);
    return response.status(500).json({ error: "The API database is unavailable." });
  }
}

let connectionPromise;
async function connectToDatabase() {
  if (!connectionPromise) {
    connectionPromise = mongoClient
      .connect()
      .then(async () => {
        const database = mongoClient.db(dbName);
        await database.command({ ping: 1 });
        console.info(`Connected to MongoDB database "${dbName}".`);
        return database;
      })
      .catch((error) => {
        connectionPromise = undefined;
        throw error;
      });
  }
  return { database: await connectionPromise };
}

async function startServer() {
  const { database } = await connectToDatabase();
  app.locals.database = database;
  app.locals.mongoClient = mongoClient;
  const server = app.listen(port, () => {
    console.info(`BookNook server listening on port ${port}.`);
  });

  const shutdown = (signal) => {
    console.info(`Received ${signal}; shutting down.`);
    server.close(async (error) => {
      if (error) {
        console.error("Failed to close the HTTP server cleanly.", error);
        process.exitCode = 1;
      }
      try {
        await mongoClient.close();
        console.info("MongoDB connection closed.");
      } catch (closeError) {
        console.error("Failed to close the MongoDB connection.", closeError);
        process.exitCode = 1;
      }
    });
  };
  process.once("SIGINT", () => shutdown("SIGINT"));
  process.once("SIGTERM", () => shutdown("SIGTERM"));
}

async function seedBooks() {
  const dataPath = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "../booknook-client/public/data.json",
  );
  const books = JSON.parse(await readFile(dataPath, "utf8"));
  if (
    !Array.isArray(books) ||
    books.some(
      (book) =>
        !book ||
        typeof book !== "object" ||
        typeof book.title !== "string" ||
        !book.title.trim() ||
        typeof book.author !== "string" ||
        !book.author.trim(),
    )
  ) {
    throw new Error("booknook-client/public/data.json must contain books with title and author.");
  }

  const { database } = await connectToDatabase();
  const collection = database.collection("books");
  const seen = new Set();
  let inserted = 0;
  let skipped = 0;

  for (const book of books) {
    const identity = JSON.stringify([book.title, book.author]);
    if (seen.has(identity)) {
      skipped += 1;
      continue;
    }
    seen.add(identity);
    if (await collection.findOne({ title: book.title, author: book.author })) {
      skipped += 1;
      continue;
    }
    await collection.insertOne(book);
    inserted += 1;
  }

  console.info(`Book seed complete: inserted ${inserted}, skipped ${skipped}.`);
}

async function migrateDatabase() {
  const { database } = await connectToDatabase();
  await database.collection("books").createIndex(
    { addedAt: -1, _id: -1 },
    { name: "books_addedAt_id_desc" },
  );
  await database.collection("books").createIndex(
    { ownerId: 1, addedAt: -1, _id: -1 },
    { name: "books_owner_addedAt_id_desc" },
  );
  await database.collection("borrows").createIndex(
    { userId: 1, borrowedAt: -1, _id: -1 },
    { name: "borrows_user_borrowedAt_id_desc" },
  );
  await database.collection("borrows").createIndex(
    { bookId: 1, userId: 1 },
    { name: "borrows_bookId_userId_unique", unique: true },
  );
  console.info("BookNook query-index migration applied.");
}

async function runCommand() {
  const command = process.argv[2];
  if (command === "--seed") {
    await seedBooks();
    await mongoClient.close();
    process.exit(0);
  }
  if (command === "--migrate") {
    await migrateDatabase();
    await mongoClient.close();
    process.exit(0);
  }
  if (command) {
    throw new Error(`Unknown command "${command}". Use --seed or --migrate.`);
  }
  await startServer();
}

if (
  !process.env.VERCEL &&
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  runCommand().catch(async (error) => {
    console.error("Server command failed.", error);
    try {
      await mongoClient.close();
    } catch (closeError) {
      console.error("Failed to close the MongoDB connection.", closeError);
    }
    process.exitCode = 1;
  });
}
