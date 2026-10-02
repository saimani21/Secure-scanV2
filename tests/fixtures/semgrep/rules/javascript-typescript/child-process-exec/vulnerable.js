const child_process = require("node:child_process");

export function executeCommand(command) {
  return child_process.exec(command);
}
