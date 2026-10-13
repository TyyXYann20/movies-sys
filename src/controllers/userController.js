import { prisma } from "../config/db.js";
import bcrypt from "bcryptjs";
import { generateToken } from "../utils/generateToken.js";
const register = async (req, res) => {
  const { name, email, password } = req.body ?? {};
  if (
    typeof name !== "string" || !name.trim() ||
    typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
    typeof password !== "string" || password.length < 6 ||
    Buffer.byteLength(password, "utf8") > 72
  ) {
    return res.status(400).json({
      error: "Name, valid email, and a password of at least 6 characters (maximum 72 bytes) are required",
    });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const userExists = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (userExists) {
    return res.status(400).json({ error: "This email already existing" });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const user = await prisma.user.create({
    data: {
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
    },
  });

  const token = generateToken(user.id, res);
  res.status(201).json({
    status: "success",
    data: {
      id: user.id,
      name: user.name,
      email: user.email,
    },
    token,
  });
};

const login = async (req, res, next) => {
  try {
    // 1. Get and validate input
    const { email, password } = req.body ?? {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        status: "fail",
        message: "Email and password are required",
      });
    }

    // 2. Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // 3. Check if user exists
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
      select: {
        id: true,
        name: true,
        email: true,
        password: true,
      },
    });

    // 4. Verify password
    const isPasswordValid = user
      ? await bcrypt.compare(password, user.password)
      : false;

    // 5. Return error if credentials are invalid
    if (!user || !isPasswordValid) {
      return res.status(401).json({
        status: "fail",
        message: "Invalid email or password",
      });
    }

    // 6. Generate JWT and set cookie
    const token = generateToken(user.id, res);

    // 7. Return successful response
    return res.status(200).json({
      status: "success",
      message: "Logged in successfully",
      data: {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
        token,
      },
    });
  } catch (error) {
    next(error);
  }
};

const logout = (req, res, next) => {
  try {
    // 1. Clear JWT cookie
    res.clearCookie("jwt", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    // 2. Return successful response
    return res.status(200).json({
      status: "success",
      message: "Logged out successfully",
    });
  } catch (error) {
    next(error);
  }
};

const profile = (req, res) => {
  res.status(200).json({ status: "success", data: req.user });
};

export { register, login, logout, profile };
