import express from "express";
import Anime from "../models/Anime.js";
import { verifyToken, isAdmin } from "../middleware/auth.js";

const router = express.Router();

// GET бүх аниме
router.get("/", async (req, res) => {
  const animes = await Anime.find();
  res.json(animes);
});

// POST шинэ аниме (ЗӨВХӨН админ)
router.post("/", verifyToken, isAdmin, async (req, res) => {
  try {
    const newAnime = new Anime(req.body);
    await newAnime.save();
    res.json(newAnime);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// PUT update аниме (ЗӨВХӨН админ)
router.put("/:id", verifyToken, isAdmin, async (req, res) => {
  const updatedAnime = await Anime.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updatedAnime);
});

// DELETE аниме (ЗӨВХӨН админ)
router.delete("/:id", verifyToken, isAdmin, async (req, res) => {
  await Anime.findByIdAndDelete(req.params.id);
  res.json({ message: "Anime deleted" });
});

export default router;
