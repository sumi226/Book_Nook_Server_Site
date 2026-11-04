import app from "./app.js";
import { closeDatabase, connectToDatabase } from "./config/database.js";
import { env } from "./config/env.js";

let httpServer;
let isShuttingDown = false;

async function startServer() {
  const { client, database } = await connectToDatabase();
  app.locals.database = database;
  app.locals.mongoClient = client;

  httpServer = await new Promise((resolve, reject) => {
    const server = app.listen(env.port);

    server.once("error", reject);
    server.once("listening", () => {
      server.removeListener("error", reject);
      resolve(server);
    });
  });

  console.info(`BookNook server listening on port ${env.port}.`);
  process.once("SIGINT", () => shutdown("SIGINT"));
  process.once("SIGTERM", () => shutdown("SIGTERM"));
}

function shutdown(signal) {
  if (isShuttingDown || !httpServer) {
    return;
  }

  isShuttingDown = true;
  console.info(`Received ${signal}; shutting down.`);

  httpServer.close(async (serverError) => {
    if (serverError) {
      console.error("Failed to close the HTTP server cleanly.", serverError);
      process.exitCode = 1;
    }

    try {
      await closeDatabase();
      console.info("MongoDB connection closed.");
    } catch (databaseError) {
      console.error("Failed to close the MongoDB connection.", databaseError);
      process.exitCode = 1;
    }
  });
}

startServer().catch(async (error) => {
  console.error("Server startup failed.", error);

  try {
    await closeDatabase();
  } catch (databaseError) {
    console.error("Failed to close the MongoDB connection.", databaseError);
  }

  process.exitCode = 1;
});
