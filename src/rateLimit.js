const { db } = require('./db');
const log = require('./log');

// Fixed-window request counters keyed by endpoint name + client IP, stored in
// Postgres so every instance behind a load balancer shares the same count (an
// in-memory counter would let each replica allow the full limit on its own).
// One atomic upsert per request: start a new window when the old one has
// ended, otherwise add one to the current window's count.
async function isRateLimited(key, maxRequests, windowMs) {
  const now = Date.now();
  const { rows } = await db.run(
    `INSERT INTO rate_limits (bucket, count, window_ends) VALUES (?, 1, ?)
     ON CONFLICT (bucket) DO UPDATE SET
       count = CASE WHEN rate_limits.window_ends <= ? THEN 1 ELSE rate_limits.count + 1 END,
       window_ends = CASE WHEN rate_limits.window_ends <= ? THEN excluded.window_ends ELSE rate_limits.window_ends END
     RETURNING count`,
    [key, now + windowMs, now, now]
  );
  return rows[0].count > maxRequests;
}

// Expired windows are just overwritten on the next hit; this removes buckets
// for clients that never came back, so the table doesn't grow forever.
async function sweepRateLimits() {
  await db.run('DELETE FROM rate_limits WHERE window_ends < ?', [Date.now()]);
}

function rateLimit(name, maxRequests, windowMs) {
  return (req, res, next) => {
    const ip = (req.get('x-forwarded-for') || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
    isRateLimited(`${name}:${ip}`, maxRequests, windowMs).then((limited) => {
      if (limited) return res.status(429).send('Too many requests. Try again shortly.');
      next();
    }).catch((err) => {
      // Never lock everyone out because the counter store hiccuped.
      log.error('[rateLimit] check failed, allowing request:', err.message);
      next();
    });
  };
}

module.exports = { isRateLimited, rateLimit, sweepRateLimits };
