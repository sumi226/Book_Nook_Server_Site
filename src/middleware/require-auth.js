import { createRemoteJWKSet, errors, jwtVerify } from "jose";
import { env } from "../config/env.js";

const jwks = createRemoteJWKSet(new URL(env.betterAuthJwksUrl));

export function createAuthenticate({ keySet, issuer, audience }) {
  return async function authenticateRequest(request, response, next) {
    const authorization = request.get("authorization");
    const match = authorization?.match(/^Bearer\s+(\S+)$/i);

    if (!match) {
      return response.status(401).json({ error: "A bearer token is required." });
    }

    let payload;

    try {
      ({ payload } = await jwtVerify(match[1], keySet, {
        issuer,
        audience,
        algorithms: ["EdDSA"],
      }));
    } catch (error) {
      if (error instanceof errors.JWKSTimeout) {
        return response
          .status(503)
          .json({ error: "Authentication service is temporarily unavailable." });
      }

      if (error instanceof errors.JOSEError) {
        return response.status(401).json({ error: "The bearer token is invalid or expired." });
      }

      return next(error);
    }

    const userId = payload.sub;
    const name = payload.name;
    const email = payload.email;

    if (
      typeof userId !== "string" ||
      !userId.trim() ||
      typeof name !== "string" ||
      !name.trim() ||
      typeof email !== "string" ||
      !email.trim()
    ) {
      return response
        .status(401)
        .json({ error: "The bearer token is missing user identity claims." });
    }

    request.auth = {
      userId: userId.trim(),
      name: name.trim(),
      email: email.trim().toLowerCase(),
    };

    return next();
  };
}

export const authenticate = createAuthenticate({
  keySet: jwks,
  issuer: env.betterAuthIssuer,
  audience: env.betterAuthAudience,
});
