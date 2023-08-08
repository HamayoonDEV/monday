import jwt from "jsonwebtoken";
import { ACCESS_TOKEN, REFRESH_TOKEN } from "../config/index.js";
import RefreshToken from "../models/token.js";

class JWTservice {
  //signAccessToken
  static signAccessToken(payload, exiryTime) {
    return jwt.sign(payload, ACCESS_TOKEN, { expiresIn: exiryTime });
  }

  //signRefreshToken
  static signRefreshToken(payload, expiryTime) {
    return jwt.sign(payload, REFRESH_TOKEN, { expiresIn: expiryTime });
  }
  //verifyAccessToken
  static verifyAccessToken(token) {
    return jwt.verify(token, ACCESS_TOKEN);
  }
  //verifyRefreshToken
  static verifyRefreshToken(token) {
    return jwt.verify(token, REFRESH_TOKEN);
  }
  //storeRefreshToken
  static async storeRefreshToken(userId, token) {
    try {
      const newToken = new RefreshToken({
        userId: userId,
        token: token,
      });
      await newToken.save();
    } catch (error) {
      console.log(error);
    }
  }
}

export default JWTservice;
