import "dotenv/config";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

app.get("/", (req, res) => res.json({ status: "ok", message: "GeoAttend Backend Running" }));

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const db = new Database(process.env.DB_PATH || "attendance.db");

const toRad = (value) => (value * Math.PI) / 180;
const haversineMeters = (lat1, lon1, lat2, lon2) => {
  const earthRadius = 6371000;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return 2 * earthRadius * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
};

const initDb = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS students (id TEXT PRIMARY KEY, name TEXT NOT NULL, password_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS lecturers (id TEXT PRIMARY KEY, name TEXT NOT NULL, password_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS units (id TEXT PRIMARY KEY, name TEXT NOT NULL, lecturer_id TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS unit_students (unit_id TEXT NOT NULL, student_id TEXT NOT NULL, PRIMARY KEY (unit_id, student_id));
    CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, unit_id TEXT NOT NULL, room_lat REAL NOT NULL, room_lng REAL NOT NULL, radius_m INTEGER NOT NULL DEFAULT 75, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS attendance_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, student_id TEXT NOT NULL, signed_at TEXT NOT NULL, latitude REAL NOT NULL, longitude REAL NOT NULL, distance_m REAL NOT NULL, device_id TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS device_bindings (student_id TEXT PRIMARY KEY, device_id TEXT NOT NULL);
  `);
};
initDb();

const auth = (req, res, next) => {
  const raw = req.headers.authorization || "";
  const token = raw.startsWith("Bearer ") ? raw.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing auth token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
};

app.post("/auth/login", (req, res) => {
  const { studentId, userId, password } = req.body;
  const idToUse = userId || studentId;
  let user = db.prepare("SELECT id, name, password_hash, 'student' as role FROM students WHERE LOWER(id) = LOWER(?)").get(idToUse);
  if (!user) user = db.prepare("SELECT id, name, password_hash, 'lecturer' as role FROM lecturers WHERE LOWER(id) = LOWER(?)").get(idToUse);
  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ userId: user.id, name: user.name, role: user.role, studentId: user.id }, JWT_SECRET, { expiresIn: "10h" });
  return res.json({ token, studentName: user.name, userName: user.name, role: user.role });
});

app.post("/auth/register", (req, res) => {
  const { id, name, password, role } = req.body;
  if (!id || !name || !password || !role) return res.status(400).json({ error: "Missing fields" });
  const hash = bcrypt.hashSync(password, 10);
  try {
    if (role === "student") {
      const regex = /^[a-zA-Z0-9]+-\d{4}\/\d{4}$/;
      if (!regex.test(id)) return res.status(400).json({ error: "ID must be like scm211-0731/2022" });
      db.prepare("INSERT INTO students (id, name, password_hash) VALUES (?, ?, ?)").run(id, name, hash);
    } else {
      db.prepare("INSERT INTO lecturers (id, name, password_hash) VALUES (?, ?, ?)").run(id, name, hash);
    }
  } catch (err) {
    return res.status(400).json({ error: "ID already exists or error occurred: " + err.message });
  }
  return res.json({ message: "Registered successfully" });
});

app.get("/units", auth, (req, res) => {
  if (req.user.role === "lecturer") {
    const rows = db.prepare("SELECT u.*, l.name as lecturer_name FROM units u JOIN lecturers l ON u.lecturer_id = l.id WHERE u.lecturer_id = ?").all(req.user.userId);
    return res.json(rows);
  } else {
    const filter = req.query.filter; // 'all' or 'my'
    if (filter === "all") {
      return res.json(db.prepare("SELECT u.*, l.name as lecturer_name FROM units u JOIN lecturers l ON u.lecturer_id = l.id").all());
    } else {
      const rows = db.prepare(`SELECT u.*, l.name as lecturer_name FROM units u JOIN unit_students us ON u.id = us.unit_id JOIN lecturers l ON u.lecturer_id = l.id WHERE us.student_id = ?`).all(req.user.userId);
      return res.json(rows);
    }
  }
});

app.post("/units/create", auth, (req, res) => {
  if (req.user.role !== "lecturer") return res.status(403).json({ error: "Only lecturers can create units" });
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Unit name required" });
  const unitId = "U" + Date.now();
  db.prepare("INSERT INTO units (id, name, lecturer_id) VALUES (?, ?, ?)").run(unitId, name, req.user.userId);
  return res.json({ message: "Unit created", unitId });
});

app.post("/units/register", auth, (req, res) => {
  if (req.user.role !== "student") return res.status(403).json({ error: "Only students can register for units" });
  const { unitId } = req.body;
  try {
    db.prepare("INSERT INTO unit_students (unit_id, student_id) VALUES (?, ?)").run(unitId, req.user.userId);
  } catch (err) {
    return res.status(400).json({ error: "Already registered for this unit" });
  }
  return res.json({ message: "Registered for unit successfully" });
});

app.get("/units/:unitId/students", auth, (req, res) => {
  if (req.user.role !== "lecturer") return res.status(403).json({ error: "Access denied" });
  const rows = db.prepare(`SELECT s.id, s.name FROM students s JOIN unit_students us ON s.id = us.student_id WHERE us.unit_id = ?`).all(req.params.unitId);
  return res.json(rows);
});

app.post("/sessions/start", auth, (req, res) => {
  if (req.user.role !== "lecturer") return res.status(403).json({ error: "Access denied" });
  const { unitId, latitude, longitude, radiusM, durationHours } = req.body;
  const sessionId = "S" + Date.now();
  const startsAt = new Date().toISOString();
  const endsAt = new Date(Date.now() + (durationHours || 2) * 60 * 60 * 1000).toISOString();
  db.prepare(`INSERT INTO sessions (id, unit_id, room_lat, room_lng, radius_m, starts_at, ends_at) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(sessionId, unitId, latitude, longitude, radiusM || 75, startsAt, endsAt);
  return res.json({ message: "Started session", sessionId });
});

app.get("/units/:unitId/sessions", auth, (req, res) => {
  if (req.user.role !== "lecturer") return res.status(403).json({ error: "Access denied" });
  const rows = db.prepare(`SELECT * FROM sessions WHERE unit_id = ? ORDER BY starts_at DESC`).all(req.params.unitId);
  return res.json(rows);
});

app.get("/sessions/:sessionId/attendance", auth, (req, res) => {
  if (req.user.role !== "lecturer") return res.status(403).json({ error: "Access denied" });
  const rows = db.prepare(`SELECT s.id, s.name, a.signed_at, a.distance_m FROM attendance_logs a JOIN students s ON s.id = a.student_id WHERE a.session_id = ?`).all(req.params.sessionId);
  return res.json(rows);
});

app.get("/units/:unitId/active-session", auth, (req, res) => {
  const session = db.prepare(`SELECT * FROM sessions WHERE unit_id = ? AND datetime('now') BETWEEN datetime(starts_at) AND datetime(ends_at) ORDER BY starts_at DESC LIMIT 1`).get(req.params.unitId);
  if (!session) return res.status(404).json({ error: "No active class session for this unit currently." });
  return res.json(session);
});

app.post("/units/:unitId/end-session", auth, (req, res) => {
  if (req.user.role !== "lecturer") return res.status(403).json({ error: "Access denied" });
  const session = db.prepare(`SELECT id FROM sessions WHERE unit_id = ? AND datetime('now') BETWEEN datetime(starts_at) AND datetime(ends_at) ORDER BY starts_at DESC LIMIT 1`).get(req.params.unitId);
  if (!session) return res.status(400).json({ error: "There is no currently active session to end." });
  db.prepare(`UPDATE sessions SET ends_at = datetime('now') WHERE id = ?`).run(session.id);
  res.json({ message: "Session explicitly ended. It is now saved as a past session." });
});

app.post("/attendance/sign", auth, (req, res) => {
  const { sessionId, latitude, longitude, deviceId } = req.body;
  if (!sessionId || latitude === undefined || longitude === undefined || !deviceId) return res.status(400).json({ error: "Missing required fields" });
  const studentId = req.user.userId;
  
  const classSession = db.prepare("SELECT * FROM sessions WHERE id = ?").get(sessionId);
  if (!classSession) return res.status(404).json({ error: "Session not found" });

  const isEnrolled = db.prepare("SELECT 1 FROM unit_students WHERE unit_id = ? AND student_id = ?").get(classSession.unit_id, studentId);
  if (!isEnrolled) return res.status(403).json({ error: "You are not registered for this unit." });

  const nowIso = new Date().toISOString();
  if (nowIso < classSession.starts_at || nowIso > classSession.ends_at) return res.status(403).json({ error: "Attendance window is closed" });

  const distanceM = haversineMeters(Number(latitude), Number(longitude), classSession.room_lat, classSession.room_lng);
  if (distanceM > classSession.radius_m) return res.status(403).json({ error: `Outside classroom zone (${distanceM.toFixed(1)}m from class center)` });

  const existingBinding = db.prepare("SELECT * FROM device_bindings WHERE student_id = ?").get(studentId);
  if (!existingBinding) {
    db.prepare("INSERT INTO device_bindings (student_id, device_id) VALUES (?, ?)").run(studentId, deviceId);
  } else if (existingBinding.device_id !== deviceId) {
    return res.status(403).json({ error: "Proxy attempt blocked: device mismatch" });
  }

  const prior = db.prepare(`SELECT id FROM attendance_logs WHERE session_id = ? AND student_id = ?`).get(sessionId, studentId);
  if (prior) return res.status(409).json({ error: "Attendance already submitted" });

  db.prepare(`INSERT INTO attendance_logs (session_id, student_id, signed_at, latitude, longitude, distance_m, device_id) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(sessionId, studentId, nowIso, latitude, longitude, distanceM, deviceId);
  return res.json({ message: "Attendance successfully verified via GPS." });
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
