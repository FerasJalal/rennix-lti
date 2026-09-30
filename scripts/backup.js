#!/usr/bin/env node
// Backs up rennix-lti's Postgres database (registrations, the LTI identity ->
// user id mappings students' history depends on, signing keys, memberships,
// audit log) as a pg_dump custom-format file.
//
//   DATABASE_URL=postgres://... node scripts/backup.js --dest /backups/lti [--keep-days 14]
//
// pg_dump must be on the PATH. Where it only exists inside the Postgres
// container (docker compose), give the full command instead:
//   PG_DUMP="docker compose exec -T postgres pg_dump -U rennix rennix_lti" node scripts/backup.js --dest ...
// Checks the dump is a valid custom-format archive, writes manifest.json next
// to it, and removes dumps older than --keep-days. Exits non-zero on failure.
// Restore: pg_restore --clean --if-exists -d "$DATABASE_URL" <file>.dump
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}

function dump(outFile) {
  return new Promise((resolve, reject) => {
    const custom = process.env.PG_DUMP;
    const url = process.env.DATABASE_URL;
    if (!custom && !url) return reject(new Error('set DATABASE_URL (or PG_DUMP with the full pg_dump command)'));
    const child = custom
      ? spawn(`${custom} --format=custom --no-owner`, { shell: true })
      : spawn('pg_dump', ['--format=custom', '--no-owner', url]);
    const out = fs.createWriteStream(outFile);
    let stderr = '';
    child.stdout.pipe(out);
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => reject(new Error(e.code === 'ENOENT' ? 'pg_dump not found on PATH (set PG_DUMP)' : e.message)));
    child.on('close', (code) => out.close(() => (code === 0 ? resolve() : reject(new Error(`pg_dump exited ${code}: ${stderr.trim().slice(0, 300)}`)))));
  });
}

async function main() {
  const dest = arg('dest', process.env.BACKUP_DIR);
  const keepDays = Number(arg('keep-days', process.env.BACKUP_KEEP_DAYS || 14));
  if (!dest) throw new Error('--dest (or BACKUP_DIR) is required');
  fs.mkdirSync(dest, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(dest, `rennix-lti-${stamp}.dump`);
  await dump(file);
  const bytes = fs.readFileSync(file);
  // Custom-format archives start with "PGDMP"; anything else is an error page or a partial file.
  if (bytes.length < 100 || bytes.subarray(0, 5).toString() !== 'PGDMP') {
    fs.rmSync(file, { force: true });
    throw new Error('pg_dump output is not a valid archive');
  }
  fs.writeFileSync(`${file}.json`, JSON.stringify({ created_at: new Date().toISOString(), file: path.basename(file), bytes: bytes.length,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex') }, null, 2));
  console.log(`backed up rennix-lti to ${file} (${bytes.length} bytes)`);

  const cutoff = Date.now() - keepDays * 24 * 60 * 60 * 1000;
  for (const name of fs.readdirSync(dest)) {
    if (!/^rennix-lti-\d{4}-\d{2}-\d{2}T.*\.dump(\.json)?$/.test(name) || name.startsWith(path.basename(file))) continue;
    const full = path.join(dest, name);
    if (fs.statSync(full).mtimeMs < cutoff) { fs.rmSync(full, { force: true }); console.log(`removed old backup ${name}`); }
  }
}

main().catch((e) => { console.error(`backup failed: ${e.message}`); process.exit(1); });
