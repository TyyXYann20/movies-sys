import express from "express";
import { config } from "dotenv";
import  userRoute from "./routes/userRoutes.js"
import { prisma, connectDB, disconnectDB } from "./config/db.js";
import { errorHandler } from "./middleware/errorMiddleware.js";

const app = express();
config();
const PORT = process.env.PORT;

// Body parsing middlwares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API endpoints
app.use("/user", userRoute)
app.use(errorHandler);

const startServer = async () => {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is missing. Set it in your .env file.");
  }
  await connectDB();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
};

startServer();

