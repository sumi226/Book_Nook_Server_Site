import app from "./src/app.js";
import { connectToDatabase } from "./src/config/database.js";

let databaseConnection;

async function ensureDatabaseConnection() {
  if (!databaseConnection) {
    databaseConnection = connectToDatabase()
      .then(({ client, database }) => {
        app.locals.database = database;
        app.locals.mongoClient = client;
      })
      .catch((error) => {
        databaseConnection = undefined;
        throw error;
      });
  }

  await databaseConnection;
}

export default async function handler(request, response) {
  try {
    await ensureDatabaseConnection();
    return app(request, response);
  } catch (error) {
    console.error("API database connection failed.", error);
    return response.status(500).json({ error: "The API database is unavailable." });
  }
}