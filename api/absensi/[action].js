// api/absensi/[action].js
// Sistem Absensi LMS
// Actions:
//   buat-pertemuan   → dosen: buat sesi pertemuan baru (wajib kelas_id)
//   list-pertemuan   → dosen/mahasiswa: lihat pertemuan per kelas_id
//   hapus-pertemuan  → dosen: hapus pertemuan
//   submit-hadir     → mahasiswa: ajukan kehadiran (validasi kelas)
//   verifikasi       → dosen: approve/tolak kehadiran mahasiswa
//   rekap            → dosen: rekap absensi semua mahasiswa per kelas
//
// PERUBAHAN v2 (kelas):
//   - kelas_id wajib saat buat-pertemuan (menggantikan matkul string)
//   - list-pertemuan: mahasiswa filter by kelas_ids miliknya
//   - submit-hadir: validasi mahasiswa terdaftar di kelas pertemuan
//   - rekap: by kelas_id bukan matkul string

import { webcrypto } from 'crypto';
import { Buffer } from 'buffer';

const crypto = webcrypto;
const FILE = 'absensi.json';
const FILE_KELAS = 'kelas.json';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-token');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  try {
    switch (action) {
      case 'buat-pertemuan':   return await handleBuatPertemuan(req, res);
      case 'list-pertemuan':   return await handleListPertemuan(req, res);
      case 'hapus-pertemuan':  return await handleHapusPertemuan(req, res);
      case 'submit-hadir':     return await handleSubmitHadir(req, res);
      case 'verifikasi':       return await handleVerifikasi(req, res);
      case 'rekap':            return await handleRekap(req, res);
      default:
        return res.status(404).json({ error: `Action tidak dikenal: ${action}` });
    }
  } catch (err) {
    console.error(`[absensi/${action}] Error:`, err);
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
  if (r.status === 404) return { data: { pertemuan: [] }, sha: null };
  if (!r.ok) throw new Error(`GitHub GET error: ${r.status}`);
  const j = await r.json();
  const decoded = Buffer.from(j.content, 'base64').toString('utf-8');
  return { data: JSON.parse(decoded), sha: j.sha };
}

async function saveData(data, sha) {
  const gh = getGHConfig(FILE);
  if (!gh) throw new Error('ENV_MISSING');
  const content = Buffer.from(JSON.stringify(data, null, 2), 'utf-8').toString('base64');
  const body = { message: 'Update absensi.json via LMS API', content };
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

async function requireAuth(req, res, roles = null) {
  const token = req.headers['x-session-token'];
  if (!token) { res.status(401).json({ error: 'Token diperlukan.' }); return null; }
  const session = await verifyToken(token);
  if (!session) { res.status(401).json({ error: 'Sesi tidak valid.' }); return null; }
  if (roles && !roles.includes(session.role)) {
    res.status(403).json({ error: 'Akses ditolak.' }); return null;
  }
  return session;
}

// ─── BUAT PERTEMUAN (Dosen only) ──────────────────────────────────────────────
// Body: { kelas_id, judul, tanggal, keterangan? }

async function handleBuatPertemuan(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireAuth(req, res, ['dosen']);
  if (!session) return;

  const { kelas_id, judul, tanggal, keterangan } = req.body || {};
  if (!kelas_id || !judul || !tanggal)
    return res.status(400).json({ error: 'kelas_id, judul, dan tanggal diperlukan.' });

  // Validasi kelas milik dosen ini
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
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data absensi.' }); }

  const { data, sha } = result;

  const newPertemuan = {
    id:         `abs_${Date.now()}`,
    kelas_id:   kelas_id.trim(),
    matkul_id:  kelas.matkul_id,   // disimpan untuk referensi
    judul:      judul.trim(),
    tanggal,
    keterangan: (keterangan || '').trim(),
    dosen_id:   session.id,
    status:     'aktif',
    created_at: new Date().toISOString(),
    kehadiran:  [],
  };

  (data.pertemuan = data.pertemuan || []).push(newPertemuan);

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan data.' }); }

  return res.status(200).json({
    message: `Pertemuan "${judul}" berhasil dibuat.`,
    pertemuan: newPertemuan,
  });
}

// ─── LIST PERTEMUAN ───────────────────────────────────────────────────────────
// Query: kelas_id (diutamakan) | matkul_id (opsional fallback)
//
// Mahasiswa: otomatis filter by kelas_ids miliknya,
//            query kelas_id harus salah satu kelas mahasiswa tsb.
// Dosen:     filter by kelas_id + dosen_id.

async function handleListPertemuan(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return;

  const { kelas_id } = req.query;

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data absensi.' }); }

  let list = result.data.pertemuan || [];

  if (session.role === 'mahasiswa') {
    // Ambil kelas mahasiswa ini
    let kelasData;
    try { kelasData = await getKelasData(); } catch { kelasData = { kelas: [] }; }

    const kelasSaya = (kelasData.kelas || [])
      .filter(k => (k.mahasiswa || []).includes(session.id))
      .map(k => k.id);

    // Filter pertemuan hanya dari kelas si mahasiswa
    list = list.filter(p => p.kelas_id && kelasSaya.includes(p.kelas_id));

    // Filter tambahan jika ada query kelas_id
    if (kelas_id) {
      if (!kelasSaya.includes(kelas_id))
        return res.status(403).json({ error: 'Anda tidak terdaftar di kelas ini.' });
      list = list.filter(p => p.kelas_id === kelas_id);
    }

    // Sembunyikan kehadiran orang lain
    list = list.map(p => ({
      ...p,
      kehadiran: p.kehadiran.filter(k => k.mhs_id === session.id),
    }));

  } else if (session.role === 'dosen') {
    list = list.filter(p => p.dosen_id === session.id);
    if (kelas_id) list = list.filter(p => p.kelas_id === kelas_id);
  } else {
    // Admin
    if (kelas_id) list = list.filter(p => p.kelas_id === kelas_id);
  }

  return res.status(200).json({ pertemuan: list });
}

// ─── HAPUS PERTEMUAN (Dosen only) ─────────────────────────────────────────────

async function handleHapusPertemuan(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireAuth(req, res, ['dosen']);
  if (!session) return;

  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'id pertemuan diperlukan.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data.' }); }

  const { data, sha } = result;
  const before = (data.pertemuan || []).length;
  data.pertemuan = (data.pertemuan || []).filter(
    p => !(p.id === id && p.dosen_id === session.id)
  );

  if (data.pertemuan.length === before)
    return res.status(404).json({ error: 'Pertemuan tidak ditemukan atau bukan milik Anda.' });

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: 'Pertemuan berhasil dihapus.' });
}

// ─── SUBMIT HADIR (Mahasiswa only) ────────────────────────────────────────────
// Body: { pertemuan_id, alasan_tipe, keterangan?, nama? }

async function handleSubmitHadir(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireAuth(req, res, ['mahasiswa']);
  if (!session) return;

  const { pertemuan_id, alasan_tipe, keterangan, nama } = req.body || {};
  if (!pertemuan_id)
    return res.status(400).json({ error: 'pertemuan_id diperlukan.' });

  const validAlasan = ['hadir', 'izin', 'sakit'];
  if (!alasan_tipe || !validAlasan.includes(alasan_tipe))
    return res.status(400).json({ error: 'alasan_tipe diperlukan: hadir, izin, atau sakit.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data absensi.' }); }

  const { data, sha } = result;
  const idx = (data.pertemuan || []).findIndex(p => p.id === pertemuan_id);
  if (idx === -1)
    return res.status(404).json({ error: 'Pertemuan tidak ditemukan.' });

  const pertemuan = data.pertemuan[idx];

  if (pertemuan.status === 'ditutup')
    return res.status(400).json({ error: 'Pertemuan sudah ditutup, tidak bisa absen.' });

  // Validasi kelas: mahasiswa harus terdaftar di kelas pertemuan ini
  if (pertemuan.kelas_id) {
    let kelasData;
    try { kelasData = await getKelasData(); } catch { kelasData = { kelas: [] }; }

    const kelas = (kelasData.kelas || []).find(k => k.id === pertemuan.kelas_id);
    if (kelas && !(kelas.mahasiswa || []).includes(session.id))
      return res.status(403).json({ error: 'Anda tidak terdaftar di kelas pertemuan ini.' });
  }

  // Validasi hari yang sama
  const ptmDate = new Date(pertemuan.tanggal);
  const now     = new Date();
  const sameDay = ptmDate.getFullYear() === now.getFullYear() &&
                  ptmDate.getMonth()    === now.getMonth()    &&
                  ptmDate.getDate()     === now.getDate();
  if (!sameDay) {
    const tgl = ptmDate.toLocaleDateString('id-ID', { weekday: 'long', day: '2-digit', month: 'long', year: 'numeric' });
    return res.status(400).json({ error: `Absensi hanya bisa dilakukan pada hari pertemuan berlangsung (${tgl}).` });
  }

  const existing = pertemuan.kehadiran.find(k => k.mhs_id === session.id);
  if (existing)
    return res.status(409).json({ error: 'Anda sudah mengajukan absensi untuk pertemuan ini.', status: existing.status });

  const entry = {
    mhs_id:       session.id,
    nim:          session.nim_nip,
    nama:         (nama || session.nim_nip).trim(),
    status:       'menunggu',
    alasan_tipe,
    keterangan:   (keterangan || '').trim(),
    submitted_at: new Date().toISOString(),
    verified_at:  null,
  };

  data.pertemuan[idx].kehadiran.push(entry);

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan absensi.' }); }

  return res.status(200).json({
    message: 'Absensi berhasil diajukan, menunggu verifikasi dosen.',
    entry,
  });
}

// ─── VERIFIKASI KEHADIRAN (Dosen only) ────────────────────────────────────────
// Body: { pertemuan_id, mhs_id, status } atau { pertemuan_id, tutup: true }

async function handleVerifikasi(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Gunakan POST.' });
  const session = await requireAuth(req, res, ['dosen']);
  if (!session) return;

  const { pertemuan_id, mhs_id, status, tutup, keterangan_dosen, nama } = req.body || {};
  if (!pertemuan_id)
    return res.status(400).json({ error: 'pertemuan_id diperlukan.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data.' }); }

  const { data, sha } = result;
  const idx = (data.pertemuan || []).findIndex(
    p => p.id === pertemuan_id && p.dosen_id === session.id
  );
  if (idx === -1)
    return res.status(404).json({ error: 'Pertemuan tidak ditemukan atau bukan milik Anda.' });

  // Tutup pertemuan
  if (tutup) {
    data.pertemuan[idx].status     = 'ditutup';
    data.pertemuan[idx].ditutup_at = new Date().toISOString();
    try { await saveData(data, sha); }
    catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }
    return res.status(200).json({ message: 'Pertemuan berhasil ditutup.' });
  }

  // Verifikasi satu mahasiswa
  if (!mhs_id || !status)
    return res.status(400).json({ error: 'mhs_id dan status diperlukan untuk verifikasi.' });
  if (!['hadir', 'izin', 'sakit', 'tidak_hadir'].includes(status))
    return res.status(400).json({ error: 'Status tidak valid. Gunakan: hadir, izin, sakit, tidak_hadir.' });

  const kidx = data.pertemuan[idx].kehadiran.findIndex(k => k.mhs_id === mhs_id);
  if (kidx === -1) {
    // Dosen set langsung walau mahasiswa belum submit
    data.pertemuan[idx].kehadiran.push({
      mhs_id,
      nim:              mhs_id,
      nama:             (nama || mhs_id),
      status,
      keterangan:       '',
      keterangan_dosen: (keterangan_dosen || '').trim(),
      submitted_at:     null,
      verified_at:      new Date().toISOString(),
    });
  } else {
    data.pertemuan[idx].kehadiran[kidx].status        = status;
    data.pertemuan[idx].kehadiran[kidx].verified_at   = new Date().toISOString();
    if (keterangan_dosen !== undefined)
      data.pertemuan[idx].kehadiran[kidx].keterangan_dosen = keterangan_dosen.trim();
  }

  try { await saveData(data, sha); }
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan.' }); }

  return res.status(200).json({ message: `Kehadiran berhasil diverifikasi sebagai "${status}".` });
}

// ─── REKAP ABSENSI (Dosen only) ───────────────────────────────────────────────
// Query: kelas_id (wajib)
// Mengembalikan semua pertemuan kelas + ringkasan kehadiran per mahasiswa

async function handleRekap(req, res) {
  const session = await requireAuth(req, res, ['dosen']);
  if (!session) return;

  const { kelas_id } = req.query;
  if (!kelas_id)
    return res.status(400).json({ error: 'Parameter kelas_id diperlukan.' });

  let result;
  try { result = await getData(); }
  catch (e) { return res.status(500).json({ error: 'Gagal membaca data absensi.' }); }

  const list = (result.data.pertemuan || []).filter(
    p => p.kelas_id === kelas_id && p.dosen_id === session.id
  );

  // Hitung statistik per mahasiswa
  const mhsMap = {};
  list.forEach(p => {
    p.kehadiran.forEach(k => {
      if (!mhsMap[k.mhs_id]) {
        mhsMap[k.mhs_id] = {
          mhs_id: k.mhs_id, nim: k.nim, nama: k.nama,
          hadir: 0, izin: 0, sakit: 0, tidak_hadir: 0, menunggu: 0,
        };
      }
      const s = k.status;
      if      (s === 'hadir')       mhsMap[k.mhs_id].hadir++;
      else if (s === 'izin')        mhsMap[k.mhs_id].izin++;
      else if (s === 'sakit')       mhsMap[k.mhs_id].sakit++;
      else if (s === 'tidak_hadir') mhsMap[k.mhs_id].tidak_hadir++;
      else                          mhsMap[k.mhs_id].menunggu++;
    });
  });

  return res.status(200).json({
    kelas_id,
    pertemuan:        list,
    total_pertemuan:  list.length,
    rekap_mahasiswa:  Object.values(mhsMap),
  });
}
