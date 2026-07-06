const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");

const dataDir = path.join(__dirname, "..", "data");
const dbPath = path.join(dataDir, "db.json");

const seedUsers = [
  { name: "Administrador", email: "admin@demo.com", password: "123456", role: "administrador" },
  { name: "Agente Soporte", email: "soporte@demo.com", password: "123456", role: "soporte" },
  { name: "Cliente Demo", email: "cliente@demo.com", password: "123456", role: "cliente" }
];

function ensureDb() {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  if (fs.existsSync(dbPath)) return;

  const now = new Date().toISOString();
  const users = seedUsers.map((user) => ({
    id: uuid(),
    name: user.name,
    email: user.email,
    passwordHash: bcrypt.hashSync(user.password, 10),
    role: user.role,
    createdAt: now
  }));
  const support = users.find((user) => user.role === "soporte");
  const client = users.find((user) => user.role === "cliente");
  const ticketId = uuid();
  const initialDb = {
    users,
    tickets: [
      {
        id: ticketId,
        title: "No puedo acceder al correo corporativo",
        description: "El sistema muestra credenciales invalidas desde esta manana.",
        category: "Accesos",
        priority: "alta",
        status: "en proceso",
        clientId: client.id,
        assigneeId: support.id,
        createdAt: now,
        updatedAt: now
      }
    ],
    history: [
      {
        id: uuid(),
        ticketId,
        userId: support.id,
        comment: "Se valido la cuenta y se inicio restablecimiento de acceso.",
        previousStatus: "abierto",
        newStatus: "en proceso",
        createdAt: now
      }
    ]
  };
  fs.writeFileSync(dbPath, JSON.stringify(initialDb, null, 2));
}

function readDb() {
  ensureDb();
  return JSON.parse(fs.readFileSync(dbPath, "utf8"));
}

function writeDb(data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
  return data;
}

module.exports = { readDb, writeDb };
