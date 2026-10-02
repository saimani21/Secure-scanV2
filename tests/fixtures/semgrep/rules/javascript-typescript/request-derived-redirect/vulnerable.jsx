export function redirect(req, res) {
  return res.redirect(req.query.next);
}
