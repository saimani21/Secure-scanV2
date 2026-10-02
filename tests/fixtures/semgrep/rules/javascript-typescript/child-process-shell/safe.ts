import * as child_process from "node:child_process";

export function start(command: string): void {
  child_process.spawn(command, [], { shell: false });
}
