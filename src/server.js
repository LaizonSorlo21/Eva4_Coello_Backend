require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const { readDb, writeDb } = require("./db");
const auth = require("./middleware/auth");
const { sanitizeUser, isValidRole, canAccessTicket } = require("./utils");

const app = express();
const port = process.env.PORT || 4000;

app.use(cors({ origin: process.env.FRONTEND_URL || "*", credentials: true }));
app.use(express.json());

function sign(user) {
  return jwt.sign(
    { id: user.id, name: user.name, email: user.email, role: user.role },
    process.env.JWT_SECRET || "dev-secret",
    { expiresIn: "8h" }
  );
}

app.get("/", (_req, res) => {
  res.json({ name: "HelpDesk Pro API", status: "online" });
});

app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "Nombre, correo y contrasena son obligatorios" });
  }
  const db = readDb();
  if (db.users.some((user) => user.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ message: "El correo ya esta registrado" });
  }
  const user = {
    id: uuid(),
    name,
    email: email.toLowerCase(),
    passwordHash: await bcrypt.hash(password, 10),
    role: "cliente",
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  writeDb(db);
  res.status(201).json({ token: sign(user), user: sanitizeUser(user) });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const db = readDb();
  const user = db.users.find((item) => item.email.toLowerCase() === String(email || "").toLowerCase());
  if (!user || !(await bcrypt.compare(password || "", user.passwordHash))) {
    return res.status(401).json({ message: "Credenciales incorrectas" });
  }
  res.json({ token: sign(user), user: sanitizeUser(user) });
});

app.get("/api/auth/profile", auth(), (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.user.id);
  res.json({ user: sanitizeUser(user) });
});

app.get("/api/users", auth(["administrador"]), (_req, res) => {
  const db = readDb();
  res.json(db.users.map(sanitizeUser));
});

app.post("/api/users", auth(["administrador"]), async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !isValidRole(role)) {
    return res.status(400).json({ message: "Datos de usuario invalidos" });
  }
  const db = readDb();
  if (db.users.some((user) => user.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ message: "El correo ya existe" });
  }
  const user = {
    id: uuid(),
    name,
    email: email.toLowerCase(),
    passwordHash: await bcrypt.hash(password, 10),
    role,
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  writeDb(db);
  res.status(201).json(sanitizeUser(user));
});

app.put("/api/users/:id", auth(["administrador"]), async (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.params.id);
  if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

  const { name, email, password, role } = req.body;
  if (role && !isValidRole(role)) return res.status(400).json({ message: "Rol invalido" });
  if (name) user.name = name;
  if (email) user.email = email.toLowerCase();
  if (role) user.role = role;
  if (password) user.passwordHash = await bcrypt.hash(password, 10);
  writeDb(db);
  res.json(sanitizeUser(user));
});

app.delete("/api/users/:id", auth(["administrador"]), (req, res) => {
  const db = readDb();
  if (req.params.id === req.user.id) {
    return res.status(400).json({ message: "No puedes eliminar tu propio usuario" });
  }
  db.users = db.users.filter((user) => user.id !== req.params.id);
  writeDb(db);
  res.json({ message: "Usuario eliminado" });
});

app.get("/api/tickets", auth(), (req, res) => {
  const db = readDb();
  const tickets = db.tickets
    .filter((ticket) => canAccessTicket(req.user, ticket))
    .map((ticket) => ({
      ...ticket,
      client: sanitizeUser(db.users.find((user) => user.id === ticket.clientId)),
      assignee: sanitizeUser(db.users.find((user) => user.id === ticket.assigneeId))
    }));
  res.json(tickets);
});

app.post("/api/tickets", auth(), (req, res) => {
  const { title, description, category, priority } = req.body;
  if (!title || !description || !category || !priority) {
    return res.status(400).json({ message: "Completa todos los campos del ticket" });
  }
  const db = readDb();
  const now = new Date().toISOString();
  const ticket = {
    id: uuid(),
    title,
    description,
    category,
    priority,
    status: "abierto",
    clientId: req.user.role === "cliente" ? req.user.id : req.body.clientId || req.user.id,
    assigneeId: req.body.assigneeId || null,
    createdAt: now,
    updatedAt: now
  };
  db.tickets.push(ticket);
  db.history.push({
    id: uuid(),
    ticketId: ticket.id,
    userId: req.user.id,
    comment: "Ticket creado",
    previousStatus: null,
    newStatus: "abierto",
    createdAt: now
  });
  writeDb(db);
  res.status(201).json(ticket);
});

app.get("/api/tickets/:id", auth(), (req, res) => {
  const db = readDb();
  const ticket = db.tickets.find((item) => item.id === req.params.id);
  if (!ticket) return res.status(404).json({ message: "Ticket no encontrado" });
  if (!canAccessTicket(req.user, ticket)) return res.status(403).json({ message: "Acceso denegado" });
  res.json({
    ...ticket,
    client: sanitizeUser(db.users.find((user) => user.id === ticket.clientId)),
    assignee: sanitizeUser(db.users.find((user) => user.id === ticket.assigneeId)),
    history: db.history
      .filter((item) => item.ticketId === ticket.id)
      .map((item) => ({ ...item, user: sanitizeUser(db.users.find((user) => user.id === item.userId)) }))
  });
});

app.put("/api/tickets/:id", auth(["soporte", "administrador"]), (req, res) => {
  const db = readDb();
  const ticket = db.tickets.find((item) => item.id === req.params.id);
  if (!ticket) return res.status(404).json({ message: "Ticket no encontrado" });
  if (!canAccessTicket(req.user, ticket)) return res.status(403).json({ message: "Acceso denegado" });

  const previousStatus = ticket.status;
  ["title", "description", "category", "priority", "status", "assigneeId"].forEach((field) => {
    if (req.body[field] !== undefined) ticket[field] = req.body[field];
  });
  ticket.updatedAt = new Date().toISOString();

  if (previousStatus !== ticket.status || req.body.comment) {
    db.history.push({
      id: uuid(),
      ticketId: ticket.id,
      userId: req.user.id,
      comment: req.body.comment || "Ticket actualizado",
      previousStatus,
      newStatus: ticket.status,
      createdAt: ticket.updatedAt
    });
  }
  writeDb(db);
  res.json(ticket);
});

app.delete("/api/tickets/:id", auth(["administrador"]), (req, res) => {
  const db = readDb();
  db.tickets = db.tickets.filter((ticket) => ticket.id !== req.params.id);
  db.history = db.history.filter((item) => item.ticketId !== req.params.id);
  writeDb(db);
  res.json({ message: "Ticket eliminado" });
});

app.get("/api/tickets/:id/history", auth(), (req, res) => {
  const db = readDb();
  const ticket = db.tickets.find((item) => item.id === req.params.id);
  if (!ticket) return res.status(404).json({ message: "Ticket no encontrado" });
  if (!canAccessTicket(req.user, ticket)) return res.status(403).json({ message: "Acceso denegado" });
  res.json(db.history.filter((item) => item.ticketId === ticket.id));
});

app.post("/api/tickets/:id/history", auth(["soporte", "administrador"]), (req, res) => {
  const db = readDb();
  const ticket = db.tickets.find((item) => item.id === req.params.id);
  if (!ticket) return res.status(404).json({ message: "Ticket no encontrado" });
  if (!canAccessTicket(req.user, ticket)) return res.status(403).json({ message: "Acceso denegado" });
  const entry = {
    id: uuid(),
    ticketId: ticket.id,
    userId: req.user.id,
    comment: req.body.comment || "Seguimiento registrado",
    previousStatus: ticket.status,
    newStatus: req.body.newStatus || ticket.status,
    createdAt: new Date().toISOString()
  };
  ticket.status = entry.newStatus;
  ticket.updatedAt = entry.createdAt;
  db.history.push(entry);
  writeDb(db);
  res.status(201).json(entry);
});

app.get("/api/reports/summary", auth(["administrador", "soporte"]), (req, res) => {
  const db = readDb();
  const visibleTickets = db.tickets.filter((ticket) => canAccessTicket(req.user, ticket));
  res.json({
    total: visibleTickets.length,
    abiertos: visibleTickets.filter((ticket) => ticket.status === "abierto").length,
    enProceso: visibleTickets.filter((ticket) => ticket.status === "en proceso").length,
    resueltos: visibleTickets.filter((ticket) => ticket.status === "resuelto").length,
    cerrados: visibleTickets.filter((ticket) => ticket.status === "cerrado").length,
    usuarios: db.users.length
  });
});

app.listen(port, () => {
  console.log(`HelpDesk Pro API running on http://localhost:${port}`);
});
