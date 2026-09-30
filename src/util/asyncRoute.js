// Express 4 doesn't catch rejections from async handlers; this forwards them
// to the error middleware (server.js) so a failed database call becomes a
// clean 500 instead of an unhandled rejection and a hung request.
function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

module.exports = { asyncRoute };
