// api/auth/[action].js
// Sistem autentikasi LMS
// Actions: login, verify, register, list-users, delete-user, update-user,
//          change-password, list-mahasiswa
// Storage: GitHub API (users.json)
// Roles: mahasiswa, dosen, admin
//
// PERUBAHAN v2 (kelas):
//   - safeUser menyertakan kelas_ids (untuk mahasiswa)
//   - register: simpan kelas_ids jika dikirim
//   - update-user: bisa update kelas_ids mahasiswa
//   - list-mahasiswa: sertakan kelas_ids di response

import { webcrypto } from 'crypto';
import { Buffer } from 'buffer';

const crypto = webcrypto;
const atob = (str) => Buffer.from(str, 'base64').toString('utf-8');
const btoa = (str) => Buffer.from(str, 'utf-8').toString('base64');

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-token, x-admin-key');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;

  try {
    switch (action) {
      case 'login':            return await handleLogin(req, res);
      case 'verify':           return await handleVerify(req, res);
      case 'register':         return await handleRegister(req, res);
      case 'list-users':       return await handleListUsers(req, res);
      case 'delete-user':      return await handleDeleteUser(req, res);
      case 'update-user':      return await handleUpdateUser(req, res);
      case 'change-password':  return await handleChangePassword(req, res);
      case 'list-mahasiswa':   return await handleListMahasiswa(req, res);
      default:
        return res.status(404).json({ error: `Action tidak dikenal: ${action}` });
    }
  } catch (err) {
    console.error(`[auth/${action}] Error:`, err);
    return res.status(500).json({ error: 'Terjadi kesalahan server.' });
  }
}

// ─── GITHUB HELPERS ──────────────────────────────────────────────────────────

const USERS_FILE = 'users.json';

function getGHConfig() {
  const { GITHUB_OWNER, GITHUB_REPO, GITHUB_PAT } = process.env;
  if (!GITHUB_OWNER || !GITHUB_REPO || !GITHUB_PAT) return null;
  return {
    url: `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${USERS_FILE}`,
    headers: {
      Authorization: `Bearer ${GITHUB_PAT}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
    }
  };
}

async function getUsers() {
  const gh = getGHConfig();
  if (!gh) throw new Error('ENV_MISSING');
  const r = await fetch(gh.url, { headers: gh.headers });
  if (!r.ok) throw new Error(`GitHub GET error: ${r.status}`);
  const j = await r.json();
  const decoded = Buffer.from(j.content, 'base64').toString('utf-8');
  return { data: JSON.parse(decoded), sha: j.sha };
}

async function saveUsers(data, sha) {
  const gh = getGHConfig();
  if (!gh) throw new Error('ENV_MISSING');
  const content = Buffer.from(JSON.stringify(data, null, 2), 'utf-8').toString('base64');
  const r = await fetch(gh.url, {
    method: 'PUT',
    headers: gh.headers,
    body: JSON.stringify({
      message: 'Update users.json via LMS auth API',
      content,
      sha,
    })
  });
  if (!r.ok) {
    const errBody = await r.text();
    throw new Error(`GitHub PUT error ${r.status}: ${errBody}`);
  }
  return true;
}

// ─── TOKEN HELPERS ────────────────────────────────────────────────────────────

async function makeToken(user) {
  const secret = process.env.SESSION_SECRET || 'lms-secret-key';
  const payload = `${user.nim_nip}|${user.role}|${user.id}|${Date.now()}`;
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(payload));
  const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return btoa(`${payload}|${sigHex}`);
}

async function verifyToken(token) {
  try {
    const secret = process.env.SESSION_SECRET || 'lms-secret-key';
    const decoded = atob(token);
    const parts = decoded.split('|');
    if (parts.length < 5) return null;

    const sigHex  = parts[parts.length - 1];
    const payload = parts.slice(0, parts.length - 1).join('|');
    const [nim_nip, role, id, tsStr] = parts;

    const ts = parseInt(tsStr);
    if (isNaN(ts)) return null;
    if (Date.now() - ts > 24 * 60 * 60 * 1000) return null;

    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
      'raw', encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(payload));
    const expectedHex = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    if (sigHex !== expectedHex) return null;
    return { nim_nip, role, id };
  } catch {
    return null;
  }
}

// ─── ADMIN CHECK ──────────────────────────────────────────────────────────────

function checkAdmin(req, res) {
  const { ADMIN_KEY } = process.env;
  const key = req.headers['x-admin-key']
    || (req.body && (req.body.adminKey || req.body.key))
    || '';
  if (!ADMIN_KEY || key !== ADMIN_KEY) {
    res.status(403).json({ error: 'Akses ditolak.' });
    return false;
  }
  return true;
}

// ─── PASSWORD HASH ────────────────────────────────────────────────────────────

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + (process.env.PASS_SALT || 'lms-salt'));
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── SAFE USER HELPER ─────────────────────────────────────────────────────────
// Normalkan field user yang aman dikembalikan ke frontend (tanpa password)

function toSafeUser(user) {
  return {
    id:         user.id,
    nim_nip:    user.nim_nip,
    nama:       user.nama,
    role:       user.role,
    jurusan:    user.jurusan    || null,
    semester:   user.semester   || null,
    mata_kuliah:user.mata_kuliah|| null,
    // v2: kelas_ids untuk mahasiswa
    kelas_ids:  user.role === 'mahasiswa' ? (user.kelas_ids || []) : undefined,
  };
}

// ─── LOGIN ────────────────────────────────────────────────────────────────────

async function handleLogin(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });

  const { nim_nip, password } = req.body || {};
  if (!nim_nip || !password)
    return res.status(400).json({ error: 'NIM/NIP dan password diperlukan.' });

  let result;
  try { result = await getUsers(); }
  catch (e) {
    const msg = e.message === 'ENV_MISSING'
      ? 'Konfigurasi server belum diatur.'
      : 'Gagal membaca data pengguna.';
    return res.status(500).json({ error: msg });
  }

  const users = result.data.users || [];
  const user  = users.find(u => u.nim_nip === nim_nip.trim());
  if (!user)
    return res.status(401).json({ error: 'NIM/NIP tidak ditemukan.' });

  // Support plain text (legacy) dan hashed
  let passwordValid = user.password === password;
  if (!passwordValid) {
    const hashed = await hashPassword(password);
    if (user.password === hashed) passwordValid = true;
  }

  if (!passwordValid)
    return res.status(401).json({ error: 'Password salah.' });

  const token = await makeToken(user);

  return res.status(200).json({
    message: 'Login berhasil.',
    token,
    user: toSafeUser(user),
  });
}

// ─── VERIFY ───────────────────────────────────────────────────────────────────

async function handleVerify(req, res) {
  const token = req.headers['x-session-token'] || (req.body && req.body.token);
  if (!token) return res.status(401).json({ valid: false, error: 'Token tidak ada.' });

  const session = await verifyToken(token);
  if (!session) return res.status(401).json({ valid: false, error: 'Sesi tidak valid atau sudah berakhir.' });

  try {
    const result = await getUsers();
    const user   = (result.data.users || []).find(u => u.id === session.id);
    if (!user) return res.status(401).json({ valid: false, error: 'Akun tidak ditemukan.' });

    return res.status(200).json({ valid: true, user: toSafeUser(user) });
  } catch {
    return res.status(200).json({ valid: true, user: session });
  }
}

// ─── REGISTER (Admin only) ────────────────────────────────────────────────────

async function handleRegister(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { nim_nip, nama, password, role, jurusan, semester, mata_kuliah, kelas_ids } = req.body || {};

  if (!nim_nip || !nama || !password || !role)
    return res.status(400).json({ error: 'nim_nip, nama, password, dan role diperlukan.' });
  if (!['mahasiswa', 'dosen', 'admin'].includes(role))
    return res.status(400).json({ error: 'Role tidak valid.' });

  let result;
  try { result = await getUsers(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data pengguna.' }); }

  const { data, sha } = result;
  const users = data.users || [];

  if (users.find(u => u.nim_nip === nim_nip.trim()))
    return res.status(409).json({ error: 'NIM/NIP sudah terdaftar.' });

  const hashedPassword = await hashPassword(password);

  const newUser = {
    id:         `usr_${Date.now()}`,
    nim_nip:    nim_nip.trim(),
    nama:       nama.trim(),
    password:   hashedPassword,
    role,
    created_at: new Date().toISOString(),
  };

  if (jurusan)     newUser.jurusan    = jurusan;
  if (role === 'mahasiswa') {
    if (semester)  newUser.semester   = parseInt(semester);
    // v2: kelas_ids
    newUser.kelas_ids = Array.isArray(kelas_ids) ? kelas_ids : [];
  }
  if (role === 'dosen' && mata_kuliah)
    newUser.mata_kuliah = Array.isArray(mata_kuliah) ? mata_kuliah : [mata_kuliah];

  users.push(newUser);
  data.users = users;

  try { await saveUsers(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan data pengguna.' }); }

  return res.status(200).json({
    message: `Pengguna ${nama} (${role}) berhasil ditambahkan.`,
    user: toSafeUser(newUser),
  });
}

// ─── LIST USERS (Admin only) ──────────────────────────────────────────────────

async function handleListUsers(req, res) {
  if (!checkAdmin(req, res)) return;

  let result;
  try { result = await getUsers(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data pengguna.' }); }

  const users = (result.data.users || []).map(u => ({ ...toSafeUser(u) }));
  return res.status(200).json({ users });
}

// ─── DELETE USER (Admin only) ─────────────────────────────────────────────────

async function handleDeleteUser(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id user diperlukan.' });

  let result;
  try { result = await getUsers(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data pengguna.' }); }

  const { data, sha } = result;
  const before  = (data.users || []).length;
  data.users    = (data.users || []).filter(u => u.id !== id);

  if (data.users.length === before)
    return res.status(404).json({ error: 'User tidak ditemukan.' });

  try { await saveUsers(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Pengguna berhasil dihapus.' });
}

// ─── UPDATE USER (Admin only) ─────────────────────────────────────────────────

async function handleUpdateUser(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { id, nama, role, jurusan, semester, mata_kuliah, kelas_ids } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id user diperlukan.' });

  let result;
  try { result = await getUsers(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data pengguna.' }); }

  const { data, sha } = result;
  const idx = (data.users || []).findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'User tidak ditemukan.' });

  if (nama)    data.users[idx].nama    = nama.trim();
  if (role && ['mahasiswa', 'dosen', 'admin'].includes(role))
    data.users[idx].role = role;
  if (jurusan) data.users[idx].jurusan = jurusan;
  if (semester)data.users[idx].semester= parseInt(semester);
  if (mata_kuliah)
    data.users[idx].mata_kuliah = Array.isArray(mata_kuliah) ? mata_kuliah : [mata_kuliah];
  // v2: update kelas_ids mahasiswa
  if (kelas_ids !== undefined && data.users[idx].role === 'mahasiswa')
    data.users[idx].kelas_ids = Array.isArray(kelas_ids) ? kelas_ids : [];

  data.users[idx].updated_at = new Date().toISOString();

  try { await saveUsers(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Data pengguna berhasil diperbarui.' });
}

// ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────

async function handleChangePassword(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });

  const token = req.headers['x-session-token'];
  if (!token) return res.status(401).json({ error: 'Token diperlukan.' });

  const session = await verifyToken(token);
  if (!session) return res.status(401).json({ error: 'Sesi tidak valid.' });

  const { old_password, new_password } = req.body || {};
  if (!old_password || !new_password)
    return res.status(400).json({ error: 'Password lama dan baru diperlukan.' });
  if (new_password.length < 6)
    return res.status(400).json({ error: 'Password baru minimal 6 karakter.' });

  let result;
  try { result = await getUsers(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data pengguna.' }); }

  const { data, sha } = result;
  const idx = (data.users || []).findIndex(u => u.id === session.id);
  if (idx === -1) return res.status(404).json({ error: 'Akun tidak ditemukan.' });

  const user       = data.users[idx];
  const oldHashed  = await hashPassword(old_password);
  const passwordValid = user.password === old_password || user.password === oldHashed;

  if (!passwordValid)
    return res.status(401).json({ error: 'Password lama tidak sesuai.' });

  data.users[idx].password   = await hashPassword(new_password);
  data.users[idx].updated_at = new Date().toISOString();

  try { await saveUsers(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Password berhasil diubah.' });
}

// ─── LIST MAHASISWA ───────────────────────────────────────────────────────────
// GET /api/auth/list-mahasiswa
// Requires valid session token (any role). Returns mahasiswa only, no passwords.
// v2: sertakan kelas_ids agar frontend bisa tahu mahasiswa sudah di kelas mana.

async function handleListMahasiswa(req, res) {
  const token = req.headers['x-session-token'];
  if (!token) return res.status(401).json({ error: 'Token diperlukan.' });
  const session = await verifyToken(token);
  if (!session) return res.status(401).json({ error: 'Sesi tidak valid.' });

  let result;
  try { result = await getUsers(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data pengguna.' }); }

  const mahasiswa = (result.data.users || [])
    .filter(u => u.role === 'mahasiswa')
    .map(u => ({
      id:        u.id,
      nim_nip:   u.nim_nip,
      nama:      u.nama,
      jurusan:   u.jurusan   || null,
      semester:  u.semester  || null,
      kelas_ids: u.kelas_ids || [],   // v2
    }));

  return res.status(200).json({ mahasiswa });
}
