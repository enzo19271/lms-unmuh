// api/kelas/[action].js
// Manajemen Kelas LMS — disimpan di kelas.json via GitHub API
//
// Actions:
//   list           → dosen/mahasiswa: list kelas (filter by matkul_id / prodi / semester / dosen_id)
//   list-admin     → admin: list semua kelas (butuh x-admin-key)
//   add            → admin: tambah kelas baru
//   update         → admin: edit kelas (nama, jadwal, dosen_id)
//   delete         → admin: hapus kelas
//   assign-mhs     → admin: assign satu mahasiswa ke kelas
//   unassign-mhs   → admin: lepas mahasiswa dari kelas
//   set-mahasiswa  → admin: set ulang seluruh daftar mahasiswa kelas (bulk)
//   my-kelas       → mahasiswa: ambil semua kelas milik mahasiswa yg login
//   kelas-dosen    → dosen: ambil semua kelas yang diajar dosen yg login

import { webcrypto } from 'crypto';
import { Buffer } from 'buffer';

const crypto = webcrypto;
const FILE = 'kelas.json';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-token, x-admin-key');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;

  try {
    switch (action) {
      case 'list':           return await handleList(req, res);
      case 'list-admin':     return await handleListAdmin(req, res);
      case 'add':            return await handleAdd(req, res);
      case 'update':         return await handleUpdate(req, res);
      case 'delete':         return await handleDelete(req, res);
      case 'assign-mhs':     return await handleAssignMhs(req, res);
      case 'unassign-mhs':   return await handleUnassignMhs(req, res);
      case 'set-mahasiswa':  return await handleSetMahasiswa(req, res);
      case 'my-kelas':       return await handleMyKelas(req, res);
      case 'kelas-dosen':    return await handleKelasDosen(req, res);
      default:
        return res.status(404).json({ error: `Action tidak dikenal: ${action}` });
    }
  } catch (err) {
    console.error(`[kelas/${action}] Error:`, err);
    return res.status(500).json({ error: 'Terjadi kesalahan server.' });
  }
}

// ─── GITHUB HELPERS ───────────────────────────────────────────────────────────

function getGHConfig() {
  const { GITHUB_OWNER, GITHUB_REPO, GITHUB_PAT } = process.env;
  if (!GITHUB_OWNER || !GITHUB_REPO || !GITHUB_PAT) return null;
  return {
    url: `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${FILE}`,
    headers: {
      Authorization: `Bearer ${GITHUB_PAT}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
    }
  };
}

async function getData() {
  const gh = getGHConfig();
  if (!gh) throw new Error('ENV_MISSING');
  const r = await fetch(gh.url, { headers: gh.headers });
  if (r.status === 404) {
    // File belum ada — kembalikan struktur kosong
    return { data: { kelas: [] }, sha: null };
  }
  if (!r.ok) throw new Error(`GitHub GET error: ${r.status}`);
  const j = await r.json();
  const decoded = Buffer.from(j.content, 'base64').toString('utf-8');
  return { data: JSON.parse(decoded), sha: j.sha };
}

async function saveData(data, sha) {
  const gh = getGHConfig();
  if (!gh) throw new Error('ENV_MISSING');
  const content = Buffer.from(JSON.stringify(data, null, 2), 'utf-8').toString('base64');
  const body = { message: 'Update kelas.json via LMS API', content };
  if (sha) body.sha = sha;
  const r = await fetch(gh.url, {
    method: 'PUT',
    headers: gh.headers,
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`GitHub PUT error ${r.status}: ${await r.text()}`);
  return true;
}

// ─── TOKEN VERIFY ─────────────────────────────────────────────────────────────

async function verifyToken(token) {
  try {
    const secret  = process.env.SESSION_SECRET || 'lms-secret-key';
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const parts   = decoded.split('|');
    if (parts.length < 5) return null;
    const sigHex  = parts[parts.length - 1];
    const payload = parts.slice(0, parts.length - 1).join('|');
    const [nim_nip, role, id, tsStr] = parts;
    const ts = parseInt(tsStr);
    if (isNaN(ts) || Date.now() - ts > 24 * 60 * 60 * 1000) return null;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sigBuf   = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
    const expected = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (sigHex !== expected) return null;
    return { nim_nip, role, id };
  } catch { return null; }
}

async function requireAuth(req, res, roles = null) {
  const token = req.headers['x-session-token'];
  if (!token) { res.status(401).json({ error: 'Token diperlukan.' }); return null; }
  const session = await verifyToken(token);
  if (!session) { res.status(401).json({ error: 'Sesi tidak valid atau kadaluarsa.' }); return null; }
  if (roles && !roles.includes(session.role)) {
    res.status(403).json({ error: 'Akses ditolak.' }); return null;
  }
  return session;
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

// ─── LIST (publik, butuh session token) ───────────────────────────────────────
// GET /api/kelas/list?matkul_id=&prodi=&semester=&dosen_id=
// Diakses dosen & mahasiswa. Tidak menyertakan array mahasiswa (privasi).

async function handleList(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return;

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({
      error: e.message === 'ENV_MISSING' ? 'Konfigurasi server belum diatur.' : 'Gagal membaca data kelas.'
    });
  }

  let list = result.data.kelas || [];

  // Filter berdasarkan query params
  const { matkul_id, prodi, semester, dosen_id } = req.query;
  if (matkul_id) list = list.filter(k => k.matkul_id === matkul_id);
  if (prodi)     list = list.filter(k => k.prodi === prodi);
  if (semester)  list = list.filter(k => k.semester === parseInt(semester));
  if (dosen_id)  list = list.filter(k => k.dosen_id === dosen_id);

  // Sembunyikan array mahasiswa dari list umum (privasi)
  const sanitized = list.map(k => ({
    id:          k.id,
    matkul_id:   k.matkul_id,
    nama_kelas:  k.nama_kelas,
    semester:    k.semester,
    prodi:       k.prodi,
    dosen_id:    k.dosen_id,
    jadwal:      k.jadwal || '',
    jumlah_mhs:  (k.mahasiswa || []).length,
    created_at:  k.created_at,
  }));

  return res.status(200).json({ kelas: sanitized });
}

// ─── LIST ADMIN (termasuk daftar mahasiswa) ───────────────────────────────────

async function handleListAdmin(req, res) {
  if (!checkAdmin(req, res)) return;

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  let list = result.data.kelas || [];

  // Filter opsional
  const { matkul_id, prodi, semester } = req.query;
  if (matkul_id) list = list.filter(k => k.matkul_id === matkul_id);
  if (prodi)     list = list.filter(k => k.prodi === prodi);
  if (semester)  list = list.filter(k => k.semester === parseInt(semester));

  return res.status(200).json({ kelas: list });
}

// ─── ADD ──────────────────────────────────────────────────────────────────────
// POST /api/kelas/add  (admin only)
// Body: { matkul_id, nama_kelas, semester, prodi, dosen_id, jadwal? }

async function handleAdd(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { matkul_id, nama_kelas, semester, prodi, dosen_id, jadwal } = req.body || {};

  if (!matkul_id || !nama_kelas || !semester || !prodi || !dosen_id) {
    return res.status(400).json({
      error: 'matkul_id, nama_kelas, semester, prodi, dan dosen_id diperlukan.'
    });
  }

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  const { data, sha } = result;
  const list = data.kelas || [];

  // Cek duplikat: matkul_id + nama_kelas yang sama tidak boleh ada dua
  const duplikat = list.find(
    k => k.matkul_id === matkul_id && k.nama_kelas.toUpperCase() === nama_kelas.trim().toUpperCase()
  );
  if (duplikat) {
    return res.status(409).json({ error: `Kelas "${nama_kelas}" untuk mata kuliah ini sudah ada.` });
  }

  const newKelas = {
    id:         `kls_${Date.now()}`,
    matkul_id:  matkul_id.trim(),
    nama_kelas: nama_kelas.trim().toUpperCase(),
    semester:   parseInt(semester),
    prodi:      prodi.trim(),
    dosen_id:   dosen_id.trim(),
    jadwal:     (jadwal || '').trim(),
    mahasiswa:  [],   // array of user id mahasiswa
    created_at: new Date().toISOString(),
  };

  list.push(newKelas);
  data.kelas = list;

  try { await saveData(data, sha); } catch (e) {
    return res.status(500).json({ error: 'Gagal menyimpan data kelas.' });
  }

  return res.status(200).json({
    message: `Kelas "${newKelas.nama_kelas}" berhasil ditambahkan.`,
    kelas: newKelas,
  });
}

// ─── UPDATE ───────────────────────────────────────────────────────────────────
// POST /api/kelas/update  (admin only)
// Body: { id, nama_kelas?, dosen_id?, jadwal?, semester?, prodi? }

async function handleUpdate(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { id, nama_kelas, dosen_id, jadwal, semester, prodi } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id kelas diperlukan.' });

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  const { data, sha } = result;
  const idx = (data.kelas || []).findIndex(k => k.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Kelas tidak ditemukan.' });

  if (nama_kelas) data.kelas[idx].nama_kelas = nama_kelas.trim().toUpperCase();
  if (dosen_id)   data.kelas[idx].dosen_id   = dosen_id.trim();
  if (jadwal !== undefined) data.kelas[idx].jadwal = jadwal.trim();
  if (semester)   data.kelas[idx].semester   = parseInt(semester);
  if (prodi)      data.kelas[idx].prodi      = prodi.trim();
  data.kelas[idx].updated_at = new Date().toISOString();

  try { await saveData(data, sha); } catch (e) {
    return res.status(500).json({ error: 'Gagal menyimpan.' });
  }

  return res.status(200).json({ message: 'Kelas berhasil diperbarui.', kelas: data.kelas[idx] });
}

// ─── DELETE ───────────────────────────────────────────────────────────────────
// POST /api/kelas/delete  (admin only)
// Body: { id }

async function handleDelete(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id kelas diperlukan.' });

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  const { data, sha } = result;
  const before  = (data.kelas || []).length;
  data.kelas    = (data.kelas || []).filter(k => k.id !== id);

  if (data.kelas.length === before) {
    return res.status(404).json({ error: 'Kelas tidak ditemukan.' });
  }

  try { await saveData(data, sha); } catch (e) {
    return res.status(500).json({ error: 'Gagal menyimpan.' });
  }

  return res.status(200).json({ message: 'Kelas berhasil dihapus.' });
}

// ─── ASSIGN MHS ───────────────────────────────────────────────────────────────
// POST /api/kelas/assign-mhs  (admin only)
// Body: { kelas_id, mhs_id }
// Tambahkan satu mahasiswa ke kelas. Jika sudah ada → diabaikan (idempotent).

async function handleAssignMhs(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { kelas_id, mhs_id } = req.body || {};
  if (!kelas_id || !mhs_id) {
    return res.status(400).json({ error: 'kelas_id dan mhs_id diperlukan.' });
  }

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  const { data, sha } = result;
  const idx = (data.kelas || []).findIndex(k => k.id === kelas_id);
  if (idx === -1) return res.status(404).json({ error: 'Kelas tidak ditemukan.' });

  if (!data.kelas[idx].mahasiswa) data.kelas[idx].mahasiswa = [];

  if (!data.kelas[idx].mahasiswa.includes(mhs_id)) {
    data.kelas[idx].mahasiswa.push(mhs_id);
    data.kelas[idx].updated_at = new Date().toISOString();

    try { await saveData(data, sha); } catch (e) {
      return res.status(500).json({ error: 'Gagal menyimpan.' });
    }
  }

  return res.status(200).json({
    message: `Mahasiswa berhasil ditambahkan ke kelas.`,
    jumlah_mhs: data.kelas[idx].mahasiswa.length,
  });
}

// ─── UNASSIGN MHS ─────────────────────────────────────────────────────────────
// POST /api/kelas/unassign-mhs  (admin only)
// Body: { kelas_id, mhs_id }

async function handleUnassignMhs(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { kelas_id, mhs_id } = req.body || {};
  if (!kelas_id || !mhs_id) {
    return res.status(400).json({ error: 'kelas_id dan mhs_id diperlukan.' });
  }

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  const { data, sha } = result;
  const idx = (data.kelas || []).findIndex(k => k.id === kelas_id);
  if (idx === -1) return res.status(404).json({ error: 'Kelas tidak ditemukan.' });

  const sebelum = (data.kelas[idx].mahasiswa || []).length;
  data.kelas[idx].mahasiswa = (data.kelas[idx].mahasiswa || []).filter(id => id !== mhs_id);

  if (data.kelas[idx].mahasiswa.length === sebelum) {
    return res.status(404).json({ error: 'Mahasiswa tidak ada di kelas ini.' });
  }

  data.kelas[idx].updated_at = new Date().toISOString();

  try { await saveData(data, sha); } catch (e) {
    return res.status(500).json({ error: 'Gagal menyimpan.' });
  }

  return res.status(200).json({
    message: 'Mahasiswa berhasil dilepas dari kelas.',
    jumlah_mhs: data.kelas[idx].mahasiswa.length,
  });
}

// ─── SET MAHASISWA (BULK) ─────────────────────────────────────────────────────
// POST /api/kelas/set-mahasiswa  (admin only)
// Body: { kelas_id, mahasiswa: ["usr_id1", "usr_id2", ...] }
// Mengganti seluruh daftar mahasiswa kelas sekaligus.

async function handleSetMahasiswa(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  if (!checkAdmin(req, res)) return;

  const { kelas_id, mahasiswa } = req.body || {};
  if (!kelas_id) return res.status(400).json({ error: 'kelas_id diperlukan.' });
  if (!Array.isArray(mahasiswa)) {
    return res.status(400).json({ error: 'mahasiswa harus berupa array of user id.' });
  }

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  const { data, sha } = result;
  const idx = (data.kelas || []).findIndex(k => k.id === kelas_id);
  if (idx === -1) return res.status(404).json({ error: 'Kelas tidak ditemukan.' });

  // Deduplicate
  data.kelas[idx].mahasiswa  = [...new Set(mahasiswa.filter(id => typeof id === 'string' && id.trim()))];
  data.kelas[idx].updated_at = new Date().toISOString();

  try { await saveData(data, sha); } catch (e) {
    return res.status(500).json({ error: 'Gagal menyimpan.' });
  }

  return res.status(200).json({
    message: `Daftar mahasiswa kelas berhasil diperbarui.`,
    jumlah_mhs: data.kelas[idx].mahasiswa.length,
  });
}

// ─── MY KELAS (Mahasiswa) ─────────────────────────────────────────────────────
// GET /api/kelas/my-kelas
// Mengembalikan semua kelas yang berisi mhs_id milik mahasiswa yang sedang login.
// Sertakan info lengkap kelas termasuk jadwal & dosen_id.

async function handleMyKelas(req, res) {
  const session = await requireAuth(req, res, ['mahasiswa']);
  if (!session) return;

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  const kelasSaya = (result.data.kelas || [])
    .filter(k => (k.mahasiswa || []).includes(session.id))
    .map(k => ({
      id:         k.id,
      matkul_id:  k.matkul_id,
      nama_kelas: k.nama_kelas,
      semester:   k.semester,
      prodi:      k.prodi,
      dosen_id:   k.dosen_id,
      jadwal:     k.jadwal || '',
    }));

  return res.status(200).json({ kelas: kelasSaya });
}

// ─── KELAS DOSEN ──────────────────────────────────────────────────────────────
// GET /api/kelas/kelas-dosen
// Mengembalikan semua kelas yang diajar oleh dosen yang sedang login.
// Sertakan jumlah mahasiswa per kelas.

async function handleKelasDosen(req, res) {
  const session = await requireAuth(req, res, ['dosen']);
  if (!session) return;

  let result;
  try { result = await getData(); } catch (e) {
    return res.status(500).json({ error: 'Gagal membaca data kelas.' });
  }

  const kelasDosen = (result.data.kelas || [])
    .filter(k => k.dosen_id === session.id)
    .map(k => ({
      id:          k.id,
      matkul_id:   k.matkul_id,
      nama_kelas:  k.nama_kelas,
      semester:    k.semester,
      prodi:       k.prodi,
      dosen_id:    k.dosen_id,
      jadwal:      k.jadwal || '',
      jumlah_mhs:  (k.mahasiswa || []).length,
      mahasiswa:   k.mahasiswa || [],   // dosen perlu tahu siapa saja agar bisa verif absensi
    }));

  return res.status(200).json({ kelas: kelasDosen });
}
