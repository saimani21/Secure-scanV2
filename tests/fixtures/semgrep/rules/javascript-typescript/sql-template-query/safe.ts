export function lookup(db: any, userId: string) {
  return db.query("SELECT * FROM users WHERE id = ?", [userId]);
}
