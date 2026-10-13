import jwt from "jsonwebtoken";
import { prisma } from "../config/db.js";

export const protect = async (req, res, next) => {
  const authorization = req.headers.authorization;
  let token;

  if (authorization) {
    const match = /^Bearer\s+(\S+)$/i.exec(authorization);
    if (!match) {
      return res.status(401).json({ error: "Invalid authorization header" });
    }
    token = match[1];
  } else {
    const cookie = req.headers.cookie?.split(";").find((entry) =>
      entry.trim().startsWith("jwt="),
    );
    if (cookie) {
      try {
        token = decodeURIComponent(cookie.trim().slice(4));
      } catch {
        return res.status(401).json({ error: "Invalid token" });
      }
    }
  }

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
    });
    if (typeof decoded.id !== "string" || !decoded.id) {
      return res.status(401).json({ error: "Invalid token" });
    }
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, name: true, email: true },
    });
    if (!user) {
      return res.status(401).json({ error: "User no longer exists" });
    }
    req.user = user;
    req.userId = user.id;
    next();
  } catch (error) {
    next(error);
  }
};
