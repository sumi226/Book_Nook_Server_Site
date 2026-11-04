import "dotenv/config";

function getRequiredEnvironmentVariable(name) {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. Copy .env.example to .env and set its value.`,
    );
  }

  return value;
}

const portValue = process.env.PORT?.trim() || "8000";
const port = Number(portValue);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}

export const env = Object.freeze({
  port,
  mongodbUri: getRequiredEnvironmentVariable("MONGODB_URI"),
  dbName: getRequiredEnvironmentVariable("DB_NAME"),
  allowedOrigin:
    process.env.ALLOWED_ORIGIN?.trim() || "http://localhost:3000",
  betterAuthIssuer: getRequiredEnvironmentVariable("BETTER_AUTH_ISSUER"),
  betterAuthAudience: getRequiredEnvironmentVariable("BETTER_AUTH_AUDIENCE"),
  betterAuthJwksUrl: getRequiredEnvironmentVariable("BETTER_AUTH_JWKS_URL"),
});

try {
  const jwksUrl = new URL(env.betterAuthJwksUrl);
  if (!["http:", "https:"].includes(jwksUrl.protocol)) {
    throw new Error();
  }
} catch {
  throw new Error("BETTER_AUTH_JWKS_URL must be an absolute HTTP or HTTPS URL.");
}
