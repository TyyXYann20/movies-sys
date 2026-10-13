export const errorHandler = (error, req, res, next) => {
  if (res.headersSent) return next(error);

  if (error.code === "P2002") {
    return res.status(409).json({ error: "This email already exists" });
  }

  const status = error.status >= 400 && error.status < 500 ? error.status : 500;
  if (status === 500) console.error(error);
  res.status(status).json({
    error: status === 500 ? "Internal server error" : error.message,
  });
};
