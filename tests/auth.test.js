import { test, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { prisma } from "../src/config/db.js";
import userRoutes from "../src/routes/userRoutes.js";
import { errorHandler } from "../src/middleware/errorMiddleware.js";

process.env.JWT_SECRET = "test-only-secret";
const user = { id: "test-user", name: "Test User", email: "test@example.com" };
const passwordHash = await bcrypt.hash("pwd123", 4);
const originalFind = prisma.user.findUnique;
const originalCreate = prisma.user.create;
let created;
prisma.user.findUnique = async ({ where, select }) => {
  if (where.id === user.id || where.email === user.email) {
    return select && !select.password ? { ...user } : { ...user, password: passwordHash };
  }
  return null;
};
prisma.user.create = async ({ data }) => {
  created = data;
  return { ...data, id: "new-user" };
};

const app = express();
app.use(express.json());
app.use("/user", userRoutes);
app.use(errorHandler);
const server = app.listen(0, "127.0.0.1");
await new Promise((resolve) => server.once("listening", resolve));
const base = `http://127.0.0.1:${server.address().port}/user`;
after(async () => {
  prisma.user.findUnique = originalFind;
  prisma.user.create = originalCreate;
  await new Promise((resolve) => server.close(resolve));
  await prisma.$disconnect();
});
const post = (path, body) => fetch(`${base}/${path}`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

test("registration awaits creation, normalizes email, hashes password, and signs user ID", async () => {
  const response = await post("register", {
    name: " New User ", email: " NEW@example.com ", password: "pwd123",
  });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.data.id, "new-user");
  assert.equal(created.email, "new@example.com");
  assert.equal(created.name, "New User");
  assert.ok(await bcrypt.compare("pwd123", created.password));
  assert.equal(jwt.verify(body.token, process.env.JWT_SECRET).id, "new-user");
  assert.equal(body.data.password, undefined);
});

test("registration rejects invalid input and existing email", async () => {
  assert.equal((await post("register", {})).status, 400);
  assert.equal((await post("register", {
    name: user.name, email: user.email, password: "pwd123",
  })).status, 400);
});

test("login rejects bad credentials and returns a usable token and cookie", async () => {
  assert.equal((await post("login", { email: user.email, password: "wrong" })).status, 401);
  const response = await post("login", { email: " TEST@example.com ", password: "pwd123" });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("set-cookie"), /jwt=.*HttpOnly/);
  const body = await response.json();
  assert.equal(jwt.verify(body.data.token, process.env.JWT_SECRET).id, user.id);
  assert.equal(body.data.user.password, undefined);
});

test("profile accepts Bearer and cookie tokens and never exposes the password", async () => {
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
  for (const headers of [{ Authorization: `Bearer ${token}` }, { Cookie: `jwt=${token}` }]) {
    const response = await fetch(`${base}/profile`, { headers });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.data.id, user.id);
    assert.equal(body.data.password, undefined);
  }
});

test("profile rejects missing, malformed, expired, and deleted-user tokens", async () => {
  for (const token of [null, "invalid", jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: -1 }), jwt.sign({ id: "deleted" }, process.env.JWT_SECRET)]) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    assert.equal((await fetch(`${base}/profile`, { headers })).status, 401);
  }
});

test("logout clears the authentication cookie", async () => {
  const response = await post("logout", {});
  assert.equal(response.status, 200);
  assert.match(response.headers.get("set-cookie"), /jwt=;/);
});
