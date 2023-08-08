import JWTservice from "../services/JWTservices.js";
import User from "../models/user.js";
import UserDTO from "../DTO/userDto.js";

const auth = async (req, res, next) => {
  //validate
  const { accessToken, refreshToken } = req.cookies;

  if (!accessToken || !refreshToken) {
    const error = {
      status: 409,
      message: "unAuthorized!!",
    };
    return next(error);
  }
  //verifyAccesstoken
  let _id;
  try {
    _id = await JWTservice.verifyAccessToken(accessToken)._id;
  } catch (error) {
    return next(error);
  }

  let user;
  try {
    user = await User.findOne({ _id });
  } catch (error) {
    return next(error);
  }
  const userDto = new UserDTO(user);
  req.user = userDto;
  next();
};
export default auth;
