import Joi from "joi";
import bcrypt from "bcryptjs";
import User from "../models/user.js";
import UserDTO from "../DTO/userDto.js";
import JWTservice from "../services/JWTservices.js";
import RefreshToken from "../models/token.js";
const passwordPattren =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[ -/:-@\[-`{-~]).{6,64}$/;

const controller = {
  async register(req, res, next) {
    //validate user input by using joi
    const userRegisterSchema = Joi.object({
      username: Joi.string().min(5).max(30).required(),
      name: Joi.string().max(30).required(),
      email: Joi.string().email().required(),
      password: Joi.string().pattern(passwordPattren).required(),
      confirmpassword: Joi.ref("password"),
    });
    //validate user Register Schema if error occurs middleware will handle
    const { error } = userRegisterSchema.validate(req.body);

    if (error) {
      next(error);
    }
    const { username, name, email, password } = req.body;
    //password hashing
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const usernameInUse = await User.exists({ username });
      const emailInUse = await User.exists({ email });
      if (usernameInUse) {
        const error = {
          status: 409,
          message:
            "username is not available please choose anOther username!!!",
        };
        return next(error);
      }
      if (emailInUse) {
        const error = {
          status: 409,
          message: "Emaile is already in use please use anOther email!!!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    //store in database
    let user;
    let accessToken;
    let refreshToken;
    try {
      const userToRegister = new User({
        username,
        name,
        email,
        password: hashedPassword,
      });
      user = await userToRegister.save();
      //genrate tokens
      accessToken = JWTservice.signAccessToken({ _id: user._id }, "30m");
      refreshToken = JWTservice.signAccessToken({ _id: user._id }, "60m");
    } catch (error) {
      return next(error);
    }
    //storing refreshToken to the database
    await JWTservice.storeRefreshToken(refreshToken, user._id);
    //send tokens to the cookie
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    //sending response
    res.status(201).json({ user, auth: true });
  },

  //login controller

  async login(req, res, next) {
    //validate user input
    const userLoginSchema = Joi.object({
      username: Joi.string().min(5).max(30).required(),
      password: Joi.string().pattern(passwordPattren).required(),
    });
    //validate user login schema
    const { error } = userLoginSchema.validate(req.body);

    if (error) {
      return next(error);
    }

    //match the user login cradiantial to gave access
    const { username, password } = req.body;
    let user;
    try {
      user = await User.findOne({ username });
      if (!user) {
        const error = {
          status: 401,
          message: "invalid username!!!",
        };
        return next(error);
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        const error = {
          status: 401,
          message: "invalid password!!!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    //intigrating cookies
    const accessToken = JWTservice.signAccessToken({ _id: user._id }, "30m");
    const refreshToken = JWTservice.signRefreshToken({ _id: user._id }, "60m");
    //update refreshToken
    try {
      await RefreshToken.updateOne(
        {
          _id: user._id,
        },
        {
          token: refreshToken,
        },
        {
          upsert: true,
        }
      );
    } catch (error) {
      return next(error);
    }

    //sending tokens to the cookies
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    const userDto = new UserDTO(user);
    res.status(200).json({ user: userDto, auth: true });
  },

  //logOut controller
  async logout(req, res, next) {
    //delete refrehToken from database
    const { refreshToken } = req.cookies;
    try {
      await RefreshToken.deleteOne({ token: refreshToken });
    } catch (error) {
      return next(error);
    }
    //clear cookies
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    //send response
    res.status(200).json({ user: null, auth: false });
  },
};
export default controller;
