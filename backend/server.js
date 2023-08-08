import express from "express";
import { PORT } from "./config/index.js";
import router from "./routes/index.js";
import connnectdb from "./database/database.js";
import errorHandler from "./middleWare/errorHandler.js";
import cookieParser from "cookie-parser";

const app = express();
app.use(cookieParser());
connnectdb();
app.use(express.json());
app.use(router);

app.use(errorHandler);
app.listen(PORT, console.log(`server is running in the PORT:${PORT}`));
