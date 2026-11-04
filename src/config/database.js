import { MongoClient } from "mongodb";
import { env } from "./env.js";

const client = new MongoClient(env.mongodbUri);

export async function connectToDatabase() {
  await client.connect();
  await client.db(env.dbName).command({ ping: 1 });

  console.info(`Connected to MongoDB database "${env.dbName}".`);

  return {
    client,
    database: client.db(env.dbName),
  };
}

export async function closeDatabase() {
  await client.close();
}
