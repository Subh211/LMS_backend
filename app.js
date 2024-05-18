import express from "express";
import { config } from "dotenv";
import cookieParser from "cookie-parser";
import router from "./routes/router.js";

config();
const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/',router)

export default app;

