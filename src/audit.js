const { db } = require('./db');
const log = require('./log');

// Never pass raw secrets, tokens, or full request bodies into `detail` --
// this table exists to answer "who did what, when", not to reconstruct
// credentials from logs.
//
// Fire-and-forget: callers don't wait on the audit write, and a failed write
// is logged rather than breaking the request it describes. The returned
// promise never rejects (await it where ordering matters, e.g. tests).
function logAdminEvent(event, detail, req) {
  const ip = req ? (req.get('x-forwarded-for') || req.socket?.remoteAddress || '') : '';
  return db.run('INSERT INTO admin_audit_log (event, detail, ip, created_at) VALUES (?, ?, ?, ?)',
    [event, detail || null, String(ip).split(',')[0].trim(), Date.now()])
    .catch((err) => log.error('[audit] write failed:', err.message));
}

module.exports = { logAdminEvent };
