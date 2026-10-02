export function lookup(db: any) {
  return db.query(`SELECT * FROM users`);
}
