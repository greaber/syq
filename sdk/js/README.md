# `@syq/sdk`

`@syq/sdk` is the official preview JavaScript and TypeScript adapter for the
[syq parallel file copier](https://github.com/greaber/syq). It invokes an
installed `syq` executable directly with an argument array; it never constructs
a shell command and it has no install script that downloads or executes a
binary.

The preview API intentionally offers raw execution and version discovery only.
A typed copy and event API will follow syq's versioned NDJSON automation
interface.

```js
import { run, version } from "@syq/sdk";

console.log(await version());

const plan = await run([
  "cp",
  "project",
  "--to",
  "server",
  "--into",
  "/backup",
  "--dry-run",
]);
console.log(new TextDecoder().decode(plan.stdout));
```

`run()` rejects with `SyqProcessError` for a nonzero process status by default.
The error retains the complete result, including stdout and stderr as byte
arrays. Pass `{ check: false }` when the caller wants to interpret the status
directly.

The `syq` executable must already be on `PATH`, or its explicit path can be
passed as `{ executable: "/path/to/syq" }`.

This package currently targets Node.js 22 or newer on Linux and macOS. Its
included declarations provide the TypeScript API without a separate package.
