import express from "express";
import controller from "../controller/authController.js";
import auth from "../middleWare/auth.js";

const router = express.Router();

router.post("/register", controller.register);
router.post("/login", controller.login);
router.post("/logout", auth, controller.logout);
router.get("/refresh", controller.refresh);
export default router;
