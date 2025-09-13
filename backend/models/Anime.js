import mongoose from "mongoose";

const animeSchema = new mongoose.Schema({
  title: { type: String, required: true },
  year: { type: Number, required: true },
  desc: { type: String, required: true },
  image: { type: String, required: true }, // image path/url
  video: { type: String, required: true }, // video path/url
});

export default mongoose.model("Anime", animeSchema);
