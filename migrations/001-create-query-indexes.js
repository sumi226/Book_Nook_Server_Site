import { closeDatabase, connectToDatabase } from "../src/config/database.js";

async function migrate() {
  try {
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

    console.info("BookNook query-index migration applied.");
  } catch (error) {
    console.error("BookNook query-index migration failed:", error);
    process.exitCode = 1;
  } finally {
    try {
      await closeDatabase();
    } catch (error) {
      console.error("Could not close the MongoDB connection cleanly:", error);
      process.exitCode = 1;
    }
  }
}

await migrate();
