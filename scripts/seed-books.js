import "dotenv/config";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MongoClient } from "mongodb";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const dataPath = resolve(
  scriptDirectory,
  "../../booknook-client/public/data.json",
);

function getRequiredEnvironmentVariable(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable ${name}.`);
  }
  return value;
}

async function main() {
  const mongodbUri = getRequiredEnvironmentVariable("MONGODB_URI");
  const dbName = getRequiredEnvironmentVariable("DB_NAME");
  const books = JSON.parse(await readFile(dataPath, "utf8"));

  if (!Array.isArray(books) || books.some(
    (book) =>
      !book ||
      typeof book !== "object" ||
      typeof book.title !== "string" ||
      !book.title.trim() ||
      typeof book.author !== "string" ||
      !book.author.trim(),
  )) {
    throw new Error("data.json must contain an array of books with title and author.");
  }

  const client = new MongoClient(mongodbUri);

  try {
    await client.connect();
    const collection = client.db(dbName).collection("books");
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

      const existing = await collection.findOne({
        title: book.title,
        author: book.author,
      });

      if (existing) {
        skipped += 1;
        continue;
      }

      await collection.insertOne(book);
      inserted += 1;
    }

    console.info(`Book seed complete: inserted ${inserted}, skipped ${skipped}.`);
  } finally {
    await client.close();
  }
}

main().catch((error) => {
  console.error("Book seed failed.", error);
  process.exitCode = 1;
});
