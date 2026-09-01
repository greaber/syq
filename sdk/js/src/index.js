import { spawn } from "node:child_process";

/** A syq process completed with a nonzero status or terminating signal. */
export class SyqProcessError extends Error {
  constructor(result) {
    const disposition = result.signal === null
      ? `status ${result.exitCode}`
      : `signal ${result.signal}`;
    super(`syq exited with ${disposition}`);
    this.name = "SyqProcessError";
    this.result = result;
  }
}

/** syq returned output that the requested operation cannot interpret. */
export class SyqOutputError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "SyqOutputError";
  }
}

function textArgument(value, label) {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string`);
  }
  return value;
}

/** Run syq without a shell and capture its complete byte output. */
export function run(args, options = {}) {
  if (!Array.isArray(args)) {
    throw new TypeError("args must be an array of strings");
  }
  const executable = textArgument(options.executable ?? "syq", "executable");
  const argumentList = args.map((argument, index) =>
    textArgument(argument, `args[${index}]`));
  const argv = [executable, ...argumentList];
  const check = options.check ?? true;

  return new Promise((resolve, reject) => {
    const child = spawn(executable, argumentList, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    let spawnError;

    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", (error) => {
      spawnError = error;
    });
    child.once("close", (exitCode, signal) => {
      if (spawnError !== undefined) {
        reject(spawnError);
        return;
      }
      const result = Object.freeze({
        argv: Object.freeze(argv),
        exitCode,
        signal,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      });
      if (check && (result.exitCode !== 0 || result.signal !== null)) {
        reject(new SyqProcessError(result));
        return;
      }
      resolve(result);
    });
  });
}

/** Return the version reported by `syq --version`. */
export async function version(options = {}) {
  const result = await run(["--version"], options);
  let output;
  try {
    output = new TextDecoder("utf-8", { fatal: true }).decode(result.stdout).trim();
  } catch (error) {
    throw new SyqOutputError("syq --version did not return UTF-8", { cause: error });
  }
  const prefix = "syq ";
  if (!output.startsWith(prefix) || output.length === prefix.length) {
    throw new SyqOutputError(`unexpected syq --version output: ${JSON.stringify(output)}`);
  }
  return output.slice(prefix.length);
}
