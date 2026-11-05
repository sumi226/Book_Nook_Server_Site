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
const defaultClientUrl =
  process.env.NODE_ENV === "production"
    ? "https://booknookclientsite.vercel.app"
    : "http://localhost:3000";
const clientUrl = (
  process.env.CLIENT_URL?.trim() || defaultClientUrl
).replace(/\/+$/, "");
const authBaseUrl = (
  process.env.BETTER_AUTH_URL?.trim() ||
  clientUrl ||
  defaultClientUrl
).replace(/\/+$/, "");

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}

export const env = Object.freeze({
  port,
  mongodbUri: getRequiredEnvironmentVariable("MONGODB_URI"),
  dbName: process.env.DB_NAME?.trim() || "booknook",
  allowedOrigin:
    (process.env.ALLOWED_ORIGIN?.trim() || clientUrl || "http://localhost:3000")
      .replace(/\/+$/, ""),
  betterAuthIssuer:
    process.env.BETTER_AUTH_ISSUER?.trim() || authBaseUrl,
  betterAuthAudience:
    process.env.BETTER_AUTH_AUDIENCE?.trim() || authBaseUrl,
  betterAuthJwksUrl:
    process.env.BETTER_AUTH_JWKS_URL?.trim() ||
    `${authBaseUrl}/api/auth/jwks`,
});

try {
  const jwksUrl = new URL(env.betterAuthJwksUrl);
  if (!["http:", "https:"].includes(jwksUrl.protocol)) {
    throw new Error();
  }
} catch {
  throw new Error("BETTER_AUTH_JWKS_URL must be an absolute HTTP or HTTPS URL.");
}
