#!/usr/bin/env node
/** Scan all Git refs and prove fixture suppressions do not hide new secrets. */
import { spawnSync, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const binary = process.env.GITLEAKS_BIN || 'gitleaks';
const config = path.join(root, '.gitleaks.toml');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-core-secret-check-'));
function scan(directory, report) {
  const result = spawnSync(binary, ['git', directory, '--log-opts=--all', '--redact',
    '--config', config, '--report-format', 'json', '--report-path', report],
  { cwd: root, encoding: 'utf8' });
  if (result.error) throw result.error;
  if (![0, 1].includes(result.status)) throw new Error(`Secret scanner failed (${result.status}).`);
  return { status: result.status, findings: JSON.parse(fs.readFileSync(report, 'utf8')) };
}
try {
  const history = scan(root, path.join(temporary, 'history.json'));
  if (history.status !== 0 || history.findings.length) {
    // Do not print matches, even for intentional fixtures.
    throw new Error(`History scan failed: ${history.findings.length} unsuppressed finding(s).`);
  }
  const fixture = path.join(temporary, 'fixture');
  fs.mkdirSync(fixture);
  const git = (...args) => execFileSync('git', ['-C', fixture, ...args], { stdio: 'pipe' });
  git('init', '-q');
  const files = ['src/canary.js', 'test/auth-record.test.js', 'test-vectors/vault-core-v1.json', 'test-vectors/bridge-v1.json'];
  for (const file of files) {
    fs.mkdirSync(path.dirname(path.join(fixture, file)), { recursive: true });
    // Random, nonfunctional value: never a real credential and never printed.
    fs.writeFileSync(path.join(fixture, file), `api_key = "${['ghp', randomBytes(18).toString('hex')].join('_')}"\n`);
  }
  git('add', '.');
  git('-c', 'user.name=security@papersafeai.com', '-c', 'user.email=security@papersafeai.com',
    '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Isolated scanner canaries');
  const canaries = scan(fixture, path.join(temporary, 'canaries.json'));
  if (canaries.status !== 1 || !files.every(file => canaries.findings.some(hit => hit.File === file))) {
    const detected = canaries.findings.map(hit => hit.File);
    const missing = files.filter(file => !detected.includes(file));
    throw new Error(`Scanner regression: status=${canaries.status}; missing paths=${missing.join(', ')}; detected paths=${detected.join(', ')}.`);
  }
  console.log('PASS: all-ref history clean; new source/test/vector canaries detected.');
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
