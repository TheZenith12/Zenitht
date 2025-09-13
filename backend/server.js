const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 5000;
const SECRET_KEY = "mysecret"; // JWT нууц түлхүүр

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB холболт
const uri = "mongodb://127.0.0.1:27017";
const client = new MongoClient(uri);

let usersAuth; // Signup/Login хэрэглэгчид
let usersCrud; // CRUD demo хэрэглэгчид
let animes;    // Anime collection

client.connect().then(() => {
  const db = client.db("animeDB");
  usersAuth = db.collection("usersAuth"); 
  usersCrud = db.collection("users");     
  animes = db.collection("animes");       
  console.log("✅ MongoDB connected");
});

// ================= AUTH =================

// 🟢 Signup
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ message: "Username, Email, Password шаардлагатай" });

  const exists = await usersAuth.findOne({ $or: [{ email }, { username }] });
  if (exists)
    return res.status(400).json({ message: "Email эсвэл Username бүртгэгдсэн байна" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, email, password: hashedPassword, role: "user" };
  await usersAuth.insertOne(newUser);

  res.json({ message: "Signup амжилттай! Та одоо login хийж болно." });
});

// 🟢 Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await usersAuth.findOne({ email });
  if (!user) return res.status(400).json({ message: "Хэрэглэгч олдсонгүй" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Нууц үг буруу" });

  const token = jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login амжилттай",
    token,
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
    },
  });
});

// ================= Middleware =================

function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Token байхгүй байна" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: "Token буруу эсвэл хугацаа дууссан" });
  }
}

// Админ шалгах middleware
function adminMiddleware(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Зөвхөн админ эрхтэй" });
  }
  next();
}

// ================= Users CRUD =================

app.get("/users", authMiddleware, async (req, res) => {
  const users = await usersCrud.find().toArray();
  res.json(users);
});

app.post("/users", authMiddleware, async (req, res) => {
  const { name, age, role } = req.body;
  if (!name || !age || !role) {
    return res.status(400).json({ message: "Бүх талбар шаардлагатай" });
  }
  const user = { name, age, role };
  const result = await usersCrud.insertOne(user);
  res.json(result);
});

app.put("/users/:id", authMiddleware, async (req, res) => {
  const id = req.params.id;
  const updatedUser = req.body;
  const result = await usersCrud.updateOne(
    { _id: new ObjectId(id) },
    { $set: updatedUser }
  );
  res.json(result);
});

app.delete("/users/:id", authMiddleware, async (req, res) => {
  const id = req.params.id;
  const result = await usersCrud.deleteOne({ _id: new ObjectId(id) });
  res.json(result);
});

// ================= Anime CRUD (Only Admin) =================

app.get("/animes", async (req, res) => {
  const allAnimes = await animes.find().toArray();
  res.json(allAnimes);
});

app.post("/animes", authMiddleware, adminMiddleware, async (req, res) => {
  const { title, desc, year, video, image } = req.body;
  if (!title || !desc) {
    return res.status(400).json({ message: "Title ба Description шаардлагатай" });
  }
  const newAnime = { title, desc, year, video, image };
  const result = await animes.insertOne(newAnime);
  res.json(result);
});

app.put("/animes/:id", authMiddleware, adminMiddleware, async (req, res) => {
  const id = req.params.id;
  const updatedAnime = req.body;
  const result = await animes.updateOne(
    { _id: new ObjectId(id) },
    { $set: updatedAnime }
  );
  res.json(result);
});

app.delete("/animes/:id", authMiddleware, adminMiddleware, async (req, res) => {
  const id = req.params.id;
  const result = await animes.deleteOne({ _id: new ObjectId(id) });
  res.json(result);
});

// ================= Server start =================
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
