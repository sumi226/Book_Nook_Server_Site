import { ObjectId } from "mongodb";
import { Router } from "express";
import { HttpError } from "../utils/http-error.js";

const categories = new Set(["Fiction", "Science", "History", "Kids", "Others"]);
const editableFields = new Set([
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

function validateBookInput(body, { partial = false } = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Request body must be a JSON object.");
  }

  const unknownFields = Object.keys(body).filter((field) => !editableFields.has(field));
  if (unknownFields.length > 0) {
    throw new HttpError(400, "Request contains unsupported book fields.", unknownFields);
  }

  const fields = Object.keys(body);
  if (fields.length === 0) {
    throw new HttpError(
      400,
      partial ? "At least one book field is required." : "Book fields are required.",
    );
  }

  const clean = {};
  const issues = [];

  for (const field of ["title", "author", "category", "image", "description"]) {
    if (!Object.hasOwn(body, field)) {
      if (!partial) {
        issues.push(`${field} is required.`);
      }
      continue;
    }

    if (typeof body[field] !== "string" || !body[field].trim()) {
      issues.push(`${field} must be a non-empty string.`);
      continue;
    }

    const value = body[field].trim();
    const maxLength = stringLimits[field];
    if (maxLength && value.length > maxLength) {
      issues.push(`${field} must be at most ${maxLength} characters.`);
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
    if (
      !Number.isInteger(body.totalCopies) ||
      body.totalCopies < 1 ||
      body.totalCopies > 100000
    ) {
      issues.push("totalCopies must be an integer between 1 and 100000.");
    } else {
      clean.totalCopies = body.totalCopies;
    }
  } else if (!partial) {
    issues.push("totalCopies is required.");
  }

  if (issues.length > 0) {
    throw new HttpError(400, "Book validation failed.", issues);
  }

  return clean;
}

function parseBookId(id) {
  if (!/^[\da-f]{24}$/i.test(id)) {
    throw new HttpError(400, "Book ID must be a valid MongoDB ObjectId.");
  }

  return new ObjectId(id);
}

function parsePositiveInteger(value, name, fallback, maximum) {
  if (value === undefined) {
    return fallback;
  }

  if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
    throw new HttpError(400, `${name} must be a positive integer.`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new HttpError(400, `${name} must not exceed ${maximum}.`);
  }

  return parsed;
}

function getBooksCollection(request) {
  const database = request.app.locals.database;
  if (!database) {
    throw new Error("MongoDB has not been attached to the Express application.");
  }

  return database.collection("books");
}

export function createBooksRouter({ authenticateRequest }) {
  const router = Router();

  router.get("/", async (request, response) => {
    const page = parsePositiveInteger(request.query.page, "page", 1, Number.MAX_SAFE_INTEGER);
    const limit = parsePositiveInteger(request.query.limit, "limit", 12, 100);
    const skip = (page - 1) * limit;

    if (!Number.isSafeInteger(skip)) {
      throw new HttpError(400, "Requested page is too large.");
    }

    const books = getBooksCollection(request);
    const [items, total] = await Promise.all([
      books
        .find({})
        .sort({ addedAt: -1, _id: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      books.countDocuments({}),
    ]);

    return response.json({
      books: items,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  });

  router.get("/mine", authenticateRequest, async (request, response) => {
    const page = parsePositiveInteger(request.query.page, "page", 1, Number.MAX_SAFE_INTEGER);
    const limit = parsePositiveInteger(request.query.limit, "limit", 12, 100);
    const skip = (page - 1) * limit;

    if (!Number.isSafeInteger(skip)) {
      throw new HttpError(400, "Requested page is too large.");
    }

    const books = getBooksCollection(request);
    const filter = { ownerId: request.auth.userId };
    const [items, total] = await Promise.all([
      books
        .find(filter)
        .sort({ addedAt: -1, _id: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      books.countDocuments(filter),
    ]);

    return response.json({
      books: items,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  });

  router.get("/:id", async (request, response) => {
    const id = parseBookId(request.params.id);
    const book = await getBooksCollection(request).findOne({ _id: id });

    if (!book) {
      throw new HttpError(404, "Book not found.");
    }

    return response.json({ book });
  });

  router.post("/", authenticateRequest, async (request, response) => {
    const input = validateBookInput(request.body);
    const now = new Date();
    const book = {
      ...input,
      addedByName: request.auth.name,
      addedByEmail: request.auth.email,
      ownerId: request.auth.userId,
      availableCopies: input.totalCopies,
      addedAt: now,
    };

    const result = await getBooksCollection(request).insertOne(book);

    return response.status(201).json({
      book: { ...book, _id: result.insertedId },
    });
  });

  router.patch("/:id", authenticateRequest, async (request, response) => {
    const id = parseBookId(request.params.id);
    const input = validateBookInput(request.body, { partial: true });
    const books = getBooksCollection(request);
    const existing = await books.findOne({
      _id: id,
      ownerId: request.auth.userId,
    });

    if (!existing) {
      throw new HttpError(404, "Book not found.");
    }

    const update = { $set: input };
    const filter = { _id: id, ownerId: request.auth.userId };

    if (Object.hasOwn(input, "totalCopies")) {
      const difference = input.totalCopies - existing.totalCopies;
      filter.totalCopies = existing.totalCopies;

      if (difference < 0) {
        filter.availableCopies = { $gte: -difference };
      }

      if (difference !== 0) {
        update.$inc = { availableCopies: difference };
      }
    }

    const result = await books.updateOne(filter, update);
    if (result.matchedCount === 0) {
      const latest = await books.findOne({
        _id: id,
        ownerId: request.auth.userId,
      });

      if (!latest) {
        throw new HttpError(404, "Book not found.");
      }

      throw new HttpError(
        409,
        latest.availableCopies < latest.totalCopies - input.totalCopies
          ? "Total copies cannot be lower than the number of copies currently borrowed."
          : "The book changed during this update. Please reload and try again.",
      );
    }

    const updatedBook = await books.findOne({
      _id: id,
      ownerId: request.auth.userId,
    });

    if (!updatedBook) {
      throw new HttpError(404, "Book not found.");
    }

    return response.json({ book: updatedBook });
  });

  router.delete("/:id", authenticateRequest, async (request, response) => {
    const id = parseBookId(request.params.id);
    const database = request.app.locals.database;
    const mongoClient = request.app.locals.mongoClient;

    if (!database || !mongoClient) {
      throw new Error("MongoDB has not been attached to the Express application.");
    }

    const session = mongoClient.startSession();

    try {
      await session.withTransaction(async () => {
        const books = database.collection("books");
        const book = await books.findOne(
          { _id: id, ownerId: request.auth.userId },
          { session },
        );

        if (!book) {
          throw new HttpError(404, "Book not found.");
        }

        const activeBorrows = await database
          .collection("borrows")
          .countDocuments({ bookId: id }, { session });

        if (activeBorrows > 0) {
          throw new HttpError(409, "A book with active borrows cannot be deleted.");
        }

        const result = await books.deleteOne(
          { _id: id, ownerId: request.auth.userId },
          { session },
        );

        if (result.deletedCount !== 1) {
          throw new HttpError(409, "The book changed during deletion. Please try again.");
        }
      });
    } finally {
      await session.endSession();
    }

    return response.status(204).end();
  });

  return router;
}
