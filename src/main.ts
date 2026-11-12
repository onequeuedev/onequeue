import { run } from './run.ts';

const code = await run({ env: process.env });
process.exitCode = code;
