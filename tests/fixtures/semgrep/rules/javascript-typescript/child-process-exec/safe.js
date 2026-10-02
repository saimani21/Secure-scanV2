const child_process = require("node:child_process");

export function listDirectory(directory) {
  return child_process.execFile("ls", ["--", directory]);
}
