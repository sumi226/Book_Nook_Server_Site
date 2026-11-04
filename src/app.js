import cors from "cors";
import express from "express";
import { env } from "./config/env.js";
import { errorHandler } from "./middleware/error-handler.js";
import { authenticate } from "./middleware/require-auth.js";
import { createBorrowsRouter } from "./routes/borrows.routes.js";
import { createBooksRouter } from "./routes/books.routes.js";

export function createApp({ authenticateRequest = authenticate } = {}) {
  const app = express();

  app.use(cors({ origin: env.allowedOrigin }));
  app.use(express.json({ limit: "1mb" }));
  app.use("/books", createBooksRouter({ authenticateRequest }));
  app.use("/borrows", createBorrowsRouter({ authenticateRequest }));
  app.use(errorHandler);

  return app;
}

const app = createApp();

export default app;
