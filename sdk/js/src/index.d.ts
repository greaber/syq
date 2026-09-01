export interface Result {
  readonly argv: readonly string[];
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
}

export interface RunOptions {
  readonly executable?: string;
  readonly check?: boolean;
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
}

export interface VersionOptions {
  readonly executable?: string;
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
}

export class SyqProcessError extends Error {
  readonly result: Result;
  constructor(result: Result);
}

export class SyqOutputError extends Error {}

export function run(
  args: readonly string[],
  options?: RunOptions,
): Promise<Result>;

export function version(options?: VersionOptions): Promise<string>;
