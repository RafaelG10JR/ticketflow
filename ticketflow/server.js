const express = require("express");
const cors = require("cors");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());
// Solo se sirve la carpeta public (así server.js nunca queda expuesto)
app.use(express.static(path.join(__dirname, "public")));

// ⚙️ VARIABLES DE ENTORNO (configúralas en Render/Azure, NO en el código)
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI || !JWT_SECRET) {
  console.error("Faltan variables de entorno MONGO_URI o JWT_SECRET");
  process.exit(1);
}

mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Conectado a MongoDB"))
  .catch(err => console.log("❌ Error:", err.message));

// 📦 MODELOS
const Usuario = mongoose.model("Usuario", new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
}));

const Ticket = mongoose.model("Ticket", new mongoose.Schema({
  titulo: { type: String, required: true },
  descripcion: String,
  prioridad: { type: String, enum: ["baja", "media", "alta"], default: "media" },
  estado: { type: String, enum: ["abierto", "en_proceso", "cerrado"], default: "abierto" },
  creadoPor: String,
  fecha: { type: Date, default: Date.now }
}));

const Tarea = mongoose.model("Tarea", new mongoose.Schema({
  titulo: { type: String, required: true },
  ticket: { type: mongoose.Schema.Types.ObjectId, ref: "Ticket", default: null },
  completada: { type: Boolean, default: false },
  creadoPor: String,
  fecha: { type: Date, default: Date.now }
}));

// 🔐 MIDDLEWARE DE AUTENTICACIÓN
function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "No autorizado" });
  }
}

// 🔐 REGISTRO Y LOGIN
app.post("/registro", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Faltan datos" });
    await new Usuario({ username, password: await bcrypt.hash(password, 10) }).save();
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: "El usuario ya existe" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await Usuario.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Credenciales incorrectas" });
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ ok: true, username, token });
});

// 🎫 TICKETS
app.get("/tickets", auth, async (req, res) => {
  res.json(await Ticket.find({ creadoPor: req.user.username }).sort({ fecha: -1 }));
});

app.post("/tickets", auth, async (req, res) => {
  const { titulo, descripcion, prioridad } = req.body;
  if (!titulo) return res.status(400).json({ error: "El título es obligatorio" });
  const t = await new Ticket({ titulo, descripcion, prioridad, creadoPor: req.user.username }).save();
  res.json(t);
});

app.put("/tickets/:id", auth, async (req, res) => {
  const { estado, prioridad } = req.body;
  const t = await Ticket.findOneAndUpdate(
    { _id: req.params.id, creadoPor: req.user.username },
    { estado, prioridad }, { new: true, omitUndefined: true });
  res.json(t);
});

app.delete("/tickets/:id", auth, async (req, res) => {
  await Ticket.deleteOne({ _id: req.params.id, creadoPor: req.user.username });
  await Tarea.deleteMany({ ticket: req.params.id, creadoPor: req.user.username });
  res.json({ ok: true });
});

// ✅ TAREAS
app.get("/tareas", auth, async (req, res) => {
  res.json(await Tarea.find({ creadoPor: req.user.username }).populate("ticket", "titulo").sort({ fecha: -1 }));
});

app.post("/tareas", auth, async (req, res) => {
  const { titulo, ticket } = req.body;
  if (!titulo) return res.status(400).json({ error: "El título es obligatorio" });
  res.json(await new Tarea({ titulo, ticket: ticket || null, creadoPor: req.user.username }).save());
});

app.put("/tareas/:id", auth, async (req, res) => {
  res.json(await Tarea.findOneAndUpdate(
    { _id: req.params.id, creadoPor: req.user.username },
    { completada: req.body.completada }, { new: true }));
});

app.delete("/tareas/:id", auth, async (req, res) => {
  await Tarea.deleteOne({ _id: req.params.id, creadoPor: req.user.username });
  res.json({ ok: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Servidor corriendo en puerto " + port));
