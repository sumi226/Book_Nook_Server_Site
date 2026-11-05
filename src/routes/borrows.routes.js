import { ObjectId } from "mongodb";
import { Router } from "express";
import { HttpError } from "../utils/http-error.js";

function parseBookId(value) {
  if (typeof value !== "string" || !/^[\da-f]{24}$/i.test(value)) {
    throw new HttpError(400, "bookId must be a valid MongoDB ObjectId.");
  }

  return new ObjectId(value);
}

function parseBorrowId(value) {
  if (!/^[\da-f]{24}$/i.test(value)) {
    throw new HttpError(400, "Borrow ID must be a valid MongoDB ObjectId.");
  }

  return new ObjectId(value);
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

function getDatabase(request) {
  const database = request.app.locals.database;
  const mongoClient = request.app.locals.mongoClient;

  if (!database || !mongoClient) {
    throw new Error("MongoDB has not been attached to the Express application.");
  }

  return { database, mongoClient };
}

export function createBorrowsRouter({ authenticateRequest }) {
  const router = Router();

  router.post("/", authenticateRequest, async (request, response) => {
    if (
      !request.body ||
      typeof request.body !== "object" ||
      Array.isArray(request.body) ||
      !Object.hasOwn(request.body, "bookId") ||
      Object.keys(request.body).some((field) => !["bookId", "durationDays"].includes(field))
    ) {
      throw new HttpError(400, "Request body must contain bookId and may contain durationDays.");
    }

    const bookId = parseBookId(request.body.bookId);
    const durationDays = request.body.durationDays ?? 7;
    if (!Number.isInteger(durationDays) || durationDays < 1 || durationDays > 30) {
      throw new HttpError(400, "durationDays must be an integer between 1 and 30.");
    }
    const { database, mongoClient } = getDatabase(request);
    const books = database.collection("books");
    const borrows = database.collection("borrows");
    const session = mongoClient.startSession();
    let borrow;

    try {
      await session.withTransaction(async () => {
        const existingBorrow = await borrows.findOne(
          { bookId, userId: request.auth.userId },
          { session },
        );

        if (existingBorrow) {
          throw new HttpError(409, "You have already borrowed this book.");
        }

        const stockUpdate = await books.updateOne(
          { _id: bookId, availableCopies: { $gt: 0 } },
          { $inc: { availableCopies: -1 } },
          { session },
        );

        if (stockUpdate.matchedCount === 0) {
          const bookExists = await books.findOne({ _id: bookId }, { session });
          if (!bookExists) {
            throw new HttpError(404, "Book not found.");
          }

          throw new HttpError(409, "No copies of this book are currently available.");
        }

        const book = await books.findOne({ _id: bookId }, { session });
        if (!book) {
          throw new HttpError(404, "Book not found.");
        }

        borrow = {
          bookId,
          bookTitle: book.title,
          userId: request.auth.userId,
          userName: request.auth.name,
          userEmail: request.auth.email,
          borrowedAt: new Date(),
          dueAt: new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000),
        };

        const result = await borrows.insertOne(borrow, { session });
        borrow._id = result.insertedId;
      });
    } finally {
      await session.endSession();
    }

    return response.status(201).json({ borrow });
  });

  router.get("/", authenticateRequest, async (request, response) => {
    const page = parsePositiveInteger(request.query.page, "page", 1, Number.MAX_SAFE_INTEGER);
    const limit = parsePositiveInteger(request.query.limit, "limit", 12, 100);
    const skip = (page - 1) * limit;

    if (!Number.isSafeInteger(skip)) {
      throw new HttpError(400, "Requested page is too large.");
    }

    const { database } = getDatabase(request);
    const borrows = database.collection("borrows");
    const filter = { userId: request.auth.userId };
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
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  });

  router.delete("/:id", authenticateRequest, async (request, response) => {
    const borrowId = parseBorrowId(request.params.id);
    const { database, mongoClient } = getDatabase(request);
    const books = database.collection("books");
    const borrows = database.collection("borrows");
    const session = mongoClient.startSession();

    try {
      await session.withTransaction(async () => {
        const borrow = await borrows.findOne(
          { _id: borrowId, userId: request.auth.userId },
          { session },
        );

        if (!borrow) {
          throw new HttpError(404, "Borrow record not found.");
        }

        const book = await books.findOne({ _id: borrow.bookId }, { session });
        if (!book || book.availableCopies >= book.totalCopies) {
          throw new HttpError(409, "The book's available-copy count cannot be safely restored.");
        }

        const stockUpdate = await books.updateOne(
          {
            _id: borrow.bookId,
            availableCopies: { $lt: book.totalCopies },
          },
          { $inc: { availableCopies: 1 } },
          { session },
        );

        if (stockUpdate.matchedCount === 0) {
          throw new HttpError(409, "The book's available-copy count changed. Please try again.");
        }

        const removal = await borrows.deleteOne(
          { _id: borrowId, userId: request.auth.userId },
          { session },
        );

        if (removal.deletedCount === 0) {
          throw new HttpError(409, "The borrow record changed. Please try again.");
        }
      });
    } finally {
      await session.endSession();
    }

    return response.status(204).end();
  });

  return router;
}
