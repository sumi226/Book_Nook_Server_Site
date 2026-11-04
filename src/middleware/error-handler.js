export function errorHandler(error, request, response, next) {
  if (response.headersSent) {
    return next(error);
  }

  if (error.type === "entity.parse.failed") {
    return response.status(400).json({ error: "Request body must be valid JSON." });
  }

  if (error.type === "entity.too.large") {
    return response.status(413).json({ error: "Request body is too large." });
  }

  if (error.code === 11000) {
    return response.status(409).json({ error: "A conflicting record already exists." });
  }

  const status = Number.isInteger(error.status) ? error.status : 500;

  if (status >= 500) {
    console.error("API request failed.", error);
    return response.status(500).json({ error: "An unexpected server error occurred." });
  }

  const payload = { error: error.message };
  if (error.details) {
    payload.details = error.details;
  }

  return response.status(status).json(payload);
}
