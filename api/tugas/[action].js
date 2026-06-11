// api/tugas/[action].js
// CRUD Tugas — disimpan di tugas.json via GitHub API
//
// Actions:
//   list              → dosen/mahasiswa: list tugas (filter by kelas_id / dosen_id)
//   add               → dosen only: buat tugas baru (wajib pilih kelas_id)
//   update            → dosen only: edit tugas miliknya
//   delete            → dosen only: hapus tugas miliknya
//   kumpul            → mahasiswa only: kumpulkan tugas
//   edit-kumpulan     → mahasiswa only: edit kiriman yang sudah ada
//   list-pengumpulan  → dosen only: lihat semua kiriman mahasiswa per tugas
//
// PERUBAHAN v2 (kelas):
//   - Field kelas_id wajib saat add
//   - handleList: mahasiswa → filter tugas by kelas_ids miliknya (via kelas.json)
//   - handleList: dosen     → filter by kelas_id atau dosen_id
//   - handleKumpul: cek mahasiswa terdaftar di kelas tugas tersebut
//   - Data tugas lama (tanpa kelas_id) tetap tampil sebagai legacy

import { webcrypto } from 'crypto';
import { Buffer } from 'buffer';

const crypto   = webcrypto;
const FILE     = 'tugas.json';
const FILE_KELAS = 'kelas.json';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-token');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  try {
    switch (action) {
      case 'list':               return await handleList(req, res);
      case 'add':                return await handleAdd(req, res);
      case 'update':             return await handleUpdate(req, res);
      case 'delete':             return await handleDelete(req, res);
      case 'kumpul':             return await handleKumpul(req, res);
      case 'edit-kumpulan':      return await handleEditKumpulan(req, res);
      case 'list-pengumpulan':   return await handleListPengumpulan(req, res);
      default:
        return res.status(404).json({ error: `Action tidak dikenal: ${action}` });
    }
  } catch (err) {
    console.error(`[tugas/${action}] Error:`, err);
    return res.status(500).json({ error: 'Terjadi kesalahan server.' });
  }
}

// ─── GITHUB HELPERS ──────────────────────────────────────────────────────────

function getGHConfig(file) {
  const { GITHUB_OWNER, GITHUB_REPO, GITHUB_PAT } = process.env;
  if (!GITHUB_OWNER || !GITHUB_REPO || !GITHUB_PAT) return null;
  return {
    url: `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${file}`,
    headers: {
      Authorization:          `Bearer ${GITHUB_PAT}`,
      Accept:                 'application/vnd.github+json',
      'Content-Type':         'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
    }
  };
}

async function getData() {
  const gh = getGHConfig(FILE);
  if (!gh) throw new Error('ENV_MISSING');
  const r = await fetch(gh.url, { headers: gh.headers });
  if (!r.ok) throw new Error(`GitHub GET error: ${r.status}`);
  const j       = await r.json();
  const decoded = Buffer.from(j.content, 'base64').toString('utf-8');
  return { data: JSON.parse(decoded), sha: j.sha };
}

async function saveData(data, sha) {
  const gh = getGHConfig(FILE);
  if (!gh) throw new Error('ENV_MISSING');
  const content = Buffer.from(JSON.stringify(data, null, 2), 'utf-8').toString('base64');
  const r = await fetch(gh.url, {
    method:  'PUT',
    headers: gh.headers,
    body:    JSON.stringify({ message: 'Update tugas.json via LMS API', content, sha })
  });
  if (!r.ok) throw new Error(`GitHub PUT error ${r.status}: ${await r.text()}`);
  return true;
}

// Ambil kelas.json — untuk keperluan filter & validasi
async function getKelasData() {
  const gh = getGHConfig(FILE_KELAS);
  if (!gh) throw new Error('ENV_MISSING');
  const r = await fetch(gh.url, { headers: gh.headers });
  if (r.status === 404) return { kelas: [] };   // file belum ada → kosong
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
    const sigBuf   = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
    const expected = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (sigHex !== expected) return null;
    return { nim_nip, role, id };
  } catch { return null; }
}

async function requireAuth(req, res) {
  const token = req.headers['x-session-token'];
  if (!token) { res.status(401).json({ error: 'Token diperlukan.' }); return null; }
  const session = await verifyToken(token);
  if (!session)  { res.status(401).json({ error: 'Token tidak valid atau kadaluarsa.' }); return null; }
  return session;
}

async function requireDosen(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return null;
  if (session.role !== 'dosen') {
    res.status(403).json({ error: 'Hanya dosen yang dapat melakukan aksi ini.' });
    return null;
  }
  return session;
}

async function requireMahasiswa(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return null;
  if (session.role !== 'mahasiswa') {
    res.status(403).json({ error: 'Hanya mahasiswa yang dapat melakukan aksi ini.' });
    return null;
  }
  return session;
}

// ─── LIST ─────────────────────────────────────────────────────────────────────
// GET /api/tugas/list?kelas_id=&dosen_id=
//
// Mahasiswa:
//   - Ambil kelas_ids mahasiswa dari kelas.json
//   - Filter tugas yang kelas_id-nya ada di kelas_ids mahasiswa
//   - Tugas legacy (tanpa kelas_id) tetap tampil jika dosen_id cocok (backward compat)
//   - Sisipkan pengumpulan_saya di tiap tugas
//
// Dosen:
//   - Filter by kelas_id (opsional) atau dosen_id (default: dosen sendiri)
//   - Jika ?kelas_id= → hanya tugas kelas itu
//
// Admin / query langsung: bisa kirim ?dosen_id= dan/atau ?kelas_id=

async function handleList(req, res) {
  const token   = req.headers['x-session-token'];
  let session   = null;
  if (token) session = await verifyToken(token);

  if (!session) {
    return res.status(401).json({ error: 'Token diperlukan.' });
  }

  let tugasResult;
  try { tugasResult = await getData(); }
  catch (e) {
    return res.status(500).json({
      error: e.message === 'ENV_MISSING' ? 'Konfigurasi server belum diatur.' : 'Gagal membaca data tugas.'
    });
  }

  let list = tugasResult.data.tugas || [];
  const { kelas_id, dosen_id } = req.query;

  if (session.role === 'mahasiswa') {
    // Ambil kelas mahasiswa ini
    let kelasData;
    try { kelasData = await getKelasData(); } catch { kelasData = { kelas: [] }; }

    const kelasSaya = (kelasData.kelas || [])
      .filter(k => (k.mahasiswa || []).includes(session.id))
      .map(k => k.id);

    // Filter: tugas harus punya kelas_id yang ada di kelasSaya,
    // ATAU tugas legacy (tanpa kelas_id) yang dosen_id-nya mengajar kelas mahasiswa ini
    const dosenKelasSaya = (kelasData.kelas || [])
      .filter(k => (k.mahasiswa || []).includes(session.id))
      .map(k => k.dosen_id);

    list = list.filter(t => {
      if (t.kelas_id) return kelasSaya.includes(t.kelas_id);
      // Legacy: tidak ada kelas_id → tampilkan jika dosen pengajar kelas mahasiswa ini
      return dosenKelasSaya.includes(t.dosen_id);
    });

    // Filter tambahan jika ada query kelas_id
    if (kelas_id) list = list.filter(t => t.kelas_id === kelas_id);

  } else if (session.role === 'dosen') {
    // Dosen: default tampilkan tugas miliknya sendiri
    list = list.filter(t => t.dosen_id === session.id);
    if (kelas_id) list = list.filter(t => t.kelas_id === kelas_id);

  } else {
    // Admin / fallback
    if (dosen_id) list = list.filter(t => t.dosen_id === dosen_id);
    if (kelas_id) list = list.filter(t => t.kelas_id === kelas_id);
  }

  const isMhs = session.role === 'mahasiswa';

  const sanitized = list.map(t => {
    const base = {
      id:            t.id,
      judul:         t.judul,
      deskripsi:     t.deskripsi || '',
      matkul:        t.matkul    || '',
      kelas_id:      t.kelas_id  || null,   // null = data legacy
      deadline:      t.deadline,
      dosen_id:      t.dosen_id,
      status:        t.status,
      created_at:    t.created_at,
      updated_at:    t.updated_at,
      jumlah_kumpul: (t.pengumpulan || []).length,
    };
    if (isMhs) {
      const milik = (t.pengumpulan || []).find(p => p.mhs_id === session.id);
      base.pengumpulan_saya = milik || null;
    }
    return base;
  });

  return res.status(200).json({ tugas: sanitized });
}

// ─── ADD ──────────────────────────────────────────────────────────────────────
// POST /api/tugas/add
// Body: { judul, deskripsi?, kelas_id, deadline }
//
// kelas_id wajib. matkul_id / nama matkul di-resolve dari kelas.json secara otomatis
// sehingga tidak perlu dikirim manual oleh frontend.

async function handleAdd(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireDosen(req, res);
  if (!session) return;

  const { judul, deskripsi, kelas_id, deadline } = req.body || {};

  if (!judul || !kelas_id || !deadline)
    return res.status(400).json({ error: 'judul, kelas_id, dan deadline diperlukan.' });

  // Validasi: kelas_id harus ada dan diajar oleh dosen ini
  let kelasData;
  try { kelasData = await getKelasData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data kelas.' }); }

  const kelas = (kelasData.kelas || []).find(k => k.id === kelas_id);
  if (!kelas)
    return res.status(404).json({ error: 'Kelas tidak ditemukan.' });
  if (kelas.dosen_id !== session.id)
    return res.status(403).json({ error: 'Anda tidak mengajar kelas ini.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data tugas.' }); }

  const { data, sha } = result;
  const newTugas = {
    id:          `tgs_${Date.now()}`,
    judul:       judul.trim(),
    deskripsi:   (deskripsi || '').trim(),
    kelas_id:    kelas_id.trim(),
    matkul_id:   kelas.matkul_id,   // disimpan untuk referensi
    deadline,
    dosen_id:    session.id,
    status:      'aktif',
    pengumpulan: [],
    created_at:  new Date().toISOString(),
  };

  (data.tugas = data.tugas || []).push(newTugas);

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({
    message: `Tugas "${judul}" berhasil ditambahkan.`,
    tugas: newTugas,
  });
}

// ─── UPDATE ───────────────────────────────────────────────────────────────────
// POST /api/tugas/update
// Body: { id, judul?, deskripsi?, deadline?, status?, kelas_id? }

async function handleUpdate(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireDosen(req, res);
  if (!session) return;

  const { id, judul, deskripsi, deadline, status, kelas_id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id tugas diperlukan.' });

  // Jika dosen ingin pindah kelas_id → validasi dulu
  if (kelas_id) {
    let kelasData;
    try { kelasData = await getKelasData(); }
    catch (e) { return res.status(500).json({ error: 'Gagal membaca data kelas.' }); }

    const kelas = (kelasData.kelas || []).find(k => k.id === kelas_id);
    if (!kelas)
      return res.status(404).json({ error: 'Kelas tidak ditemukan.' });
    if (kelas.dosen_id !== session.id)
      return res.status(403).json({ error: 'Anda tidak mengajar kelas ini.' });
  }

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data.' }); }

  const { data, sha } = result;
  const idx = (data.tugas || []).findIndex(t => t.id === id && t.dosen_id === session.id);
  if (idx === -1)
    return res.status(404).json({ error: 'Tugas tidak ditemukan atau bukan milik Anda.' });

  if (judul)                   data.tugas[idx].judul     = judul.trim();
  if (deskripsi !== undefined) data.tugas[idx].deskripsi = deskripsi.trim();
  if (deadline)                data.tugas[idx].deadline  = deadline;
  if (kelas_id)                data.tugas[idx].kelas_id  = kelas_id.trim();
  if (status && ['aktif', 'ditutup', 'selesai'].includes(status))
    data.tugas[idx].status = status;
  data.tugas[idx].updated_at = new Date().toISOString();

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Tugas berhasil diperbarui.' });
}

// ─── DELETE ───────────────────────────────────────────────────────────────────

async function handleDelete(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireDosen(req, res);
  if (!session) return;

  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id tugas diperlukan.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data.' }); }

  const { data, sha } = result;
  const before  = (data.tugas || []).length;
  data.tugas    = (data.tugas || []).filter(t => !(t.id === id && t.dosen_id === session.id));
  if (data.tugas.length === before)
    return res.status(404).json({ error: 'Tugas tidak ditemukan atau bukan milik Anda.' });

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Tugas berhasil dihapus.' });
}

// ─── KUMPUL ───────────────────────────────────────────────────────────────────
// POST /api/tugas/kumpul
// Body: { tugas_id, link, catatan, nama, nim }
// Mahasiswa kumpulkan tugas. Validasi: mahasiswa harus terdaftar di kelas tugas tsb.

async function handleKumpul(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireMahasiswa(req, res);
  if (!session) return;

  const { tugas_id, link, catatan, nama, nim } = req.body || {};
  if (!tugas_id)
    return res.status(400).json({ error: 'tugas_id diperlukan.' });
  if (!link && !catatan)
    return res.status(400).json({ error: 'Isi minimal link file atau catatan pengumpulan.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data.' }); }

  const { data, sha } = result;
  const idx = (data.tugas || []).findIndex(t => t.id === tugas_id);
  if (idx === -1)
    return res.status(404).json({ error: 'Tugas tidak ditemukan.' });

  const tugas = data.tugas[idx];

  if (tugas.status !== 'aktif')
    return res.status(400).json({ error: 'Tugas ini sudah ditutup, tidak bisa dikumpulkan.' });

  // Validasi kelas: jika tugas punya kelas_id, mahasiswa harus terdaftar di kelas itu
  if (tugas.kelas_id) {
    let kelasData;
    try { kelasData = await getKelasData(); } catch { kelasData = { kelas: [] }; }

    const kelas = (kelasData.kelas || []).find(k => k.id === tugas.kelas_id);
    if (kelas && !(kelas.mahasiswa || []).includes(session.id)) {
      return res.status(403).json({ error: 'Anda tidak terdaftar di kelas tugas ini.' });
    }
  }

  if (!tugas.pengumpulan) tugas.pengumpulan = [];
  const sudahKumpul = tugas.pengumpulan.find(p => p.mhs_id === session.id);
  if (sudahKumpul)
    return res.status(400).json({ error: 'Kamu sudah mengumpulkan tugas ini. Gunakan edit-kumpulan untuk mengubah.' });

  const entry = {
    mhs_id:       session.id,
    nim:          nim || session.nim_nip,
    nama:         (nama || '').trim(),
    link:         (link || '').trim(),
    catatan:      (catatan || '').trim(),
    submitted_at: new Date().toISOString(),
  };
  tugas.pengumpulan.push(entry);

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Tugas berhasil dikumpulkan!', pengumpulan: entry });
}

// ─── EDIT KUMPULAN ────────────────────────────────────────────────────────────
// POST /api/tugas/edit-kumpulan
// Body: { tugas_id, link, catatan }

async function handleEditKumpulan(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireMahasiswa(req, res);
  if (!session) return;

  const { tugas_id, link, catatan } = req.body || {};
  if (!tugas_id)
    return res.status(400).json({ error: 'tugas_id diperlukan.' });
  if (link === undefined && catatan === undefined)
    return res.status(400).json({ error: 'Isi minimal link file atau catatan.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data.' }); }

  const { data, sha } = result;
  const idx = (data.tugas || []).findIndex(t => t.id === tugas_id);
  if (idx === -1)
    return res.status(404).json({ error: 'Tugas tidak ditemukan.' });

  const tugas = data.tugas[idx];
  if (tugas.status !== 'aktif')
    return res.status(400).json({ error: 'Tugas sudah ditutup, tidak bisa diedit.' });

  if (!tugas.pengumpulan) tugas.pengumpulan = [];
  const pIdx = tugas.pengumpulan.findIndex(p => p.mhs_id === session.id);
  if (pIdx === -1)
    return res.status(404).json({ error: 'Kamu belum mengumpulkan tugas ini. Gunakan kumpul terlebih dahulu.' });

  if (link    !== undefined) tugas.pengumpulan[pIdx].link    = link.trim();
  if (catatan !== undefined) tugas.pengumpulan[pIdx].catatan = catatan.trim();
  tugas.pengumpulan[pIdx].updated_at = new Date().toISOString();

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Kiriman berhasil diperbarui.', pengumpulan: tugas.pengumpulan[pIdx] });
}

// ─── LIST PENGUMPULAN (DOSEN) ─────────────────────────────────────────────────
// GET /api/tugas/list-pengumpulan?tugas_id=
// Dosen melihat semua kiriman mahasiswa untuk satu tugas miliknya.

async function handleListPengumpulan(req, res) {
  const session = await requireDosen(req, res);
  if (!session) return;

  const { tugas_id } = req.query;
  if (!tugas_id)
    return res.status(400).json({ error: 'tugas_id diperlukan.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data.' }); }

  const tugas = (result.data.tugas || []).find(t => t.id === tugas_id);
  if (!tugas)
    return res.status(404).json({ error: 'Tugas tidak ditemukan.' });

  if (tugas.dosen_id !== session.id)
    return res.status(403).json({ error: 'Anda bukan pemilik tugas ini.' });

  return res.status(200).json({
    tugas_id:    tugas.id,
    judul:       tugas.judul,
    kelas_id:    tugas.kelas_id  || null,
    matkul_id:   tugas.matkul_id || null,
    deadline:    tugas.deadline,
    status:      tugas.status,
    pengumpulan: tugas.pengumpulan || [],
    total:       (tugas.pengumpulan || []).length,
  });
}
