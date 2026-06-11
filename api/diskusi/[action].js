// api/diskusi/[action].js
// Sistem Diskusi LMS — Chat per Kelas
// Actions:
//   kirim   → dosen/mahasiswa: kirim pesan ke ruang diskusi kelas
//   pesan   → dosen/mahasiswa: ambil pesan terbaru suatu kelas
//   hapus   → dosen/pengirim: hapus pesan (soft delete)
//
// PERUBAHAN v2 (kelas):
//   - Room key berdasarkan kelas_id (bukan nama matkul string)
//   - kirim/pesan/hapus wajib kirim kelas_id
//   - Validasi: pengirim harus anggota kelas (mahasiswa) atau dosen pengampu
//   - Backward compat: room lama by matkul-string masih bisa diakses via ?matkul= (read-only)

import { webcrypto } from 'crypto';
import { Buffer } from 'buffer';

const crypto = webcrypto;
const FILE = 'diskusi.json';
const FILE_KELAS = 'kelas.json';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-token');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  try {
    switch (action) {
      case 'kirim':  return await handleKirim(req, res);
      case 'pesan':  return await handlePesan(req, res);
      case 'hapus':  return await handleHapus(req, res);
      default:
        return res.status(404).json({ error: `Action tidak dikenal: ${action}` });
    }
  } catch (err) {
    console.error(`[diskusi/${action}] Error:`, err);
    return res.status(500).json({ error: 'Terjadi kesalahan server.' });
  }
}

// ─── GITHUB HELPERS ───────────────────────────────────────────────────────────

function getGHConfig(file) {
  const { GITHUB_OWNER, GITHUB_REPO, GITHUB_PAT } = process.env;
  if (!GITHUB_OWNER || !GITHUB_REPO || !GITHUB_PAT) return null;
  return {
    url: `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${file}`,
    headers: {
      Authorization: `Bearer ${GITHUB_PAT}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
    }
  };
}

async function getData() {
  const gh = getGHConfig(FILE);
  if (!gh) throw new Error('ENV_MISSING');
  const r = await fetch(gh.url, { headers: gh.headers });
  if (r.status === 404) return { data: { rooms: {} }, sha: null };
  if (!r.ok) throw new Error(`GitHub GET error: ${r.status}`);
  const j = await r.json();
  const decoded = Buffer.from(j.content, 'base64').toString('utf-8');
  return { data: JSON.parse(decoded), sha: j.sha };
}

async function saveData(data, sha) {
  const gh = getGHConfig(FILE);
  if (!gh) throw new Error('ENV_MISSING');

  // Batasi tiap room maksimal 200 pesan terbaru (FIFO)
  const MAX_PER_ROOM = 200;
  if (data.rooms) {
    for (const key of Object.keys(data.rooms)) {
      const msgs = data.rooms[key];
      if (Array.isArray(msgs) && msgs.length > MAX_PER_ROOM)
        data.rooms[key] = msgs.slice(msgs.length - MAX_PER_ROOM);
    }
  }

  const content = Buffer.from(JSON.stringify(data, null, 2), 'utf-8').toString('base64');
  const body = { message: 'Update diskusi.json via LMS API', content };
  if (sha) body.sha = sha;
  const r = await fetch(gh.url, {
    method: 'PUT',
    headers: gh.headers,
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`GitHub PUT error ${r.status}: ${await r.text()}`);
  return true;
}

async function getKelasData() {
  const gh = getGHConfig(FILE_KELAS);
  if (!gh) throw new Error('ENV_MISSING');
  const r = await fetch(gh.url, { headers: gh.headers });
  if (r.status === 404) return { kelas: [] };
  if (!r.ok) throw new Error(`GitHub GET kelas error: ${r.status}`);
  const j = await r.json();
  const decoded = Buffer.from(j.content, 'base64').toString('utf-8');
  return JSON.parse(decoded);
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
    const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
    const expected = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (sigHex !== expected) return null;
    return { nim_nip, role, id };
  } catch { return null; }
}

async function requireAuth(req, res) {
  const token = req.headers['x-session-token'];
  if (!token) { res.status(401).json({ error: 'Token diperlukan.' }); return null; }
  const session = await verifyToken(token);
  if (!session) { res.status(401).json({ error: 'Sesi tidak valid.' }); return null; }
  return session;
}

// ─── VALIDASI AKSES KELAS ─────────────────────────────────────────────────────
// Cek apakah user boleh mengakses diskusi kelas tertentu.
// Mahasiswa harus terdaftar, dosen harus mengajar kelas tsb.
// Return kelas object jika valid, null + send response jika tidak.

async function validateKelasAccess(session, kelas_id, res) {
  let kelasData;
  try { kelasData = await getKelasData(); }
  catch (e) { res.status(500).json({ error: 'Gagal membaca data kelas.' }); return null; }

  const kelas = (kelasData.kelas || []).find(k => k.id === kelas_id);
  if (!kelas) { res.status(404).json({ error: 'Kelas tidak ditemukan.' }); return null; }

  if (session.role === 'mahasiswa') {
    if (!(kelas.mahasiswa || []).includes(session.id)) {
      res.status(403).json({ error: 'Anda tidak terdaftar di kelas ini.' });
      return null;
    }
  } else if (session.role === 'dosen') {
    if (kelas.dosen_id !== session.id) {
      res.status(403).json({ error: 'Anda tidak mengajar kelas ini.' });
      return null;
    }
  }
  // admin lolos tanpa cek

  return kelas;
}

// ─── KIRIM PESAN ──────────────────────────────────────────────────────────────
// Body: { kelas_id, isi, nama }

async function handleKirim(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireAuth(req, res);
  if (!session) return;

  const { kelas_id, isi, nama } = req.body || {};
  if (!kelas_id || !isi || !isi.trim())
    return res.status(400).json({ error: 'kelas_id dan isi pesan diperlukan.' });
  if (isi.trim().length > 2000)
    return res.status(400).json({ error: 'Pesan terlalu panjang (maks 2000 karakter).' });

  // Validasi akses
  const kelas = await validateKelasAccess(session, kelas_id, res);
  if (!kelas) return;

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data diskusi.' }); }

  const { data, sha } = result;
  if (!data.rooms) data.rooms = {};
  // Room key = kelas_id langsung (aman sebagai JSON key)
  const key = `kelas_${kelas_id}`;
  if (!data.rooms[key]) data.rooms[key] = [];

  const pesan = {
    id:          `msg_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    sender_id:   session.id,
    sender_nim:  session.nim_nip,
    sender_nama: (nama || session.nim_nip).trim(),
    role:        session.role,
    kelas_id,
    isi:         isi.trim(),
    created_at:  new Date().toISOString(),
    dihapus:     false,
  };

  data.rooms[key].push(pesan);

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan pesan.' }); }

  return res.status(200).json({ message: 'Pesan terkirim.', pesan });
}

// ─── AMBIL PESAN ──────────────────────────────────────────────────────────────
// Query: kelas_id (wajib), limit (default 50), before_id (pagination opsional)

async function handlePesan(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return;

  const { kelas_id, limit, before_id } = req.query;
  if (!kelas_id)
    return res.status(400).json({ error: 'Parameter kelas_id diperlukan.' });

  // Validasi akses
  const kelas = await validateKelasAccess(session, kelas_id, res);
  if (!kelas) return;

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data diskusi.' }); }

  const key  = `kelas_${kelas_id}`;
  let list   = (result.data.rooms?.[key] || []).filter(p => !p.dihapus);

  if (before_id) {
    const idx = list.findIndex(p => p.id === before_id);
    if (idx > 0) list = list.slice(0, idx);
  }

  const n = Math.min(parseInt(limit) || 50, 100);
  list = list.slice(-n);

  return res.status(200).json({ pesan: list, total: list.length });
}

// ─── HAPUS PESAN ──────────────────────────────────────────────────────────────
// Body: { kelas_id, pesan_id }
// Dosen bisa hapus semua pesan di kelasnya; mahasiswa hanya pesannya sendiri.

async function handleHapus(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireAuth(req, res);
  if (!session) return;

  const { kelas_id, pesan_id } = req.body || {};
  if (!kelas_id || !pesan_id)
    return res.status(400).json({ error: 'kelas_id dan pesan_id diperlukan.' });

  // Validasi akses kelas
  const kelas = await validateKelasAccess(session, kelas_id, res);
  if (!kelas) return;

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data.' }); }

  const { data, sha } = result;
  const key  = `kelas_${kelas_id}`;
  const list = data.rooms?.[key];
  if (!list) return res.status(404).json({ error: 'Ruang diskusi tidak ditemukan.' });

  const idx = list.findIndex(p => p.id === pesan_id);
  if (idx === -1) return res.status(404).json({ error: 'Pesan tidak ditemukan.' });

  const pesan = list[idx];
  if (session.role === 'mahasiswa' && pesan.sender_id !== session.id)
    return res.status(403).json({ error: 'Anda hanya bisa menghapus pesan Anda sendiri.' });

  data.rooms[key][idx].dihapus    = true;
  data.rooms[key][idx].dihapus_at = new Date().toISOString();

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Pesan berhasil dihapus.' });
}
