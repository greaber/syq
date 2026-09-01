import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

import { run, SyqProcessError, version } from "../src/index.js";

const fakeSyq = `#!/bin/sh
case "$1" in
  --version)
    printf 'syq 9.8.7\\n'
    ;;
  emit)
    printf '%s' "$2"
    printf 'diagnostic' >&2
    ;;
  fail)
    printf 'partial'
    printf 'failed' >&2
    exit 23
    ;;
  *)
    exit 2
    ;;
esac
`;

let directory;
let executable;

before(async () => {
  directory = await mkdtemp(join(tmpdir(), "syq-js-test-"));
  executable = join(directory, "syq");
  await writeFile(executable, fakeSyq, "utf8");
  await chmod(executable, 0o755);
});

after(async () => {
  await rm(directory, { recursive: true, force: true });
});

test("version validates the executable output", async () => {
  assert.equal(await version({ executable }), "9.8.7");
});

test("run preserves one argument with shell metacharacters", async () => {
  const argument = "a path; $(not-a-command)";
  const result = await run(["emit", argument], { executable });

  assert.deepEqual(result.argv, [executable, "emit", argument]);
  assert.equal(result.stdout.toString(), argument);
  assert.equal(result.stderr.toString(), "diagnostic");
});

test("nonzero results are retained", async () => {
  await assert.rejects(
    run(["fail"], { executable }),
    (error) => {
      assert.ok(error instanceof SyqProcessError);
      assert.equal(error.result.exitCode, 23);
      assert.equal(error.result.stdout.toString(), "partial");
      assert.equal(error.result.stderr.toString(), "failed");
      return true;
    },
  );
});

test("nonzero results can be returned", async () => {
  const result = await run(["fail"], { executable, check: false });
  assert.equal(result.exitCode, 23);
});

test("a missing executable rejects with the spawn error", async () => {
  await assert.rejects(
    run(["--version"], { executable: join(directory, "missing-syq") }),
    { code: "ENOENT" },
  );
});
