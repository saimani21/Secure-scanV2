export function start(runner: { spawn: Function }, command: string): void {
  runner.spawn(command, [], { shell: true });
}
