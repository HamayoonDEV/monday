import mongoose from "mongoose";

const { Schema } = mongoose;

const tokenSchema = Schema(
  {
    userId: { type: String, required: true },
    token: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("RefreshToken", tokenSchema, "token");
