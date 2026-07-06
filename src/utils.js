function sanitizeUser(user) {
  if (!user) return null;
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}

function isValidRole(role) {
  return ["cliente", "soporte", "administrador"].includes(role);
}

function canAccessTicket(user, ticket) {
  if (user.role === "administrador") return true;
  if (user.role === "soporte") return ticket.assigneeId === user.id || !ticket.assigneeId;
  return ticket.clientId === user.id;
}

module.exports = { sanitizeUser, isValidRole, canAccessTicket };
