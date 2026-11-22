/**
 * Finds the base images named in the repository's Dockerfiles (FROM lines).
 *
 * Trivy `fs` checks a Dockerfile's settings but not the operating-system packages inside the image it starts FROM, and the
 * action never pulls images. So these are reported as coverage gaps: the image reference only (no code, no paths).
 * Bounded on purpose: a few thousand directory entries, 256 KB per file, 20 images.
 */
import { opendir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { scrubText } from './redact/scrub.ts';

const MAX_ENTRIES = 5000;
const MAX_DEPTH = 6;
const MAX_FILE_BYTES = 256 * 1024;
export const MAX_BASE_IMAGES = 20;
const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', '.venv', 'venv', 'dist', 'build', '.terraform']);
const DOCKERFILE = /^(?:Dockerfile|Containerfile)(?:[.-][A-Za-z0-9._-]+)?$|\.(?:dockerfile|containerfile)$/i;

/** The images FROM lines start from, minus `scratch`, earlier build stages and images that use a build argument ($VAR). */
export function parseBaseImages(text: string): string[] {
  const stages = new Set<string>();
  const out: string[] = [];
  // Line continuations ("\") join into one instruction.
  for (const line of text.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
    const m = /^\s*FROM\s+((?:--\S+\s+)*)(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (!m) continue;
    const image = m[2]!;
    if (m[3]) stages.add(m[3].toLowerCase());
    if (image.toLowerCase() === 'scratch' || stages.has(image.toLowerCase()) || image.includes('$')) continue;
    out.push(image);
  }
  return out;
}

export async function findBaseImages(workspace: string): Promise<string[]> {
  const found = new Set<string>();
  let visited = 0;

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > MAX_DEPTH || visited >= MAX_ENTRIES || found.size >= MAX_BASE_IMAGES) return;
    let handle;
    try {
      handle = await opendir(dir);
    } catch {
      return;
    }
    for await (const entry of handle) {
      if (++visited > MAX_ENTRIES) break;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk(join(dir, entry.name), depth + 1);
      } else if (entry.isFile() && DOCKERFILE.test(entry.name)) {
        try {
          const buf = await readFile(join(dir, entry.name));
          for (const img of parseBaseImages(buf.subarray(0, MAX_FILE_BYTES).toString('utf8'))) {
            // A reference is a name and a tag or digest; scrub it like every other string, without entropy (digests are hex).
            const clean = scrubText(img, { maxLen: 200, entropy: false });
            if (clean === img) found.add(img);
          }
        } catch {
          /* unreadable file: skip */
        }
      }
      if (found.size >= MAX_BASE_IMAGES) break;
    }
  }

  await walk(workspace, 0);
  return [...found].sort().slice(0, MAX_BASE_IMAGES);
}
