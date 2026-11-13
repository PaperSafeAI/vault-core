import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';
import { readHidden } from '../bin/terminal-input.js';

function terminal() {
  const input = new PassThrough();
  input.isRaw = false;
  input.setRawMode = value => { input.isRaw = value; };
  const output = new PassThrough();
  let shown = '';
  output.on('data', chunk => { shown += chunk.toString(); });
  return { input, output, shown: () => shown };
}

describe('hidden terminal passphrase', () => {
  it('preserves UTF-8 characters split across every byte boundary without echo', async () => {
    const t = terminal();
    const pending = readHidden('Passphrase: ', t);
    for (const byte of Buffer.from('héllo 🔐 दुनिया\r')) t.input.write(Buffer.from([byte]));
    expect(await pending).toBe('héllo 🔐 दुनिया');
    expect(t.shown()).toBe('Passphrase: \n');
    expect(t.input.isRaw).toBe(false);
    expect(t.input.listenerCount('data')).toBe(0);
  });
  it('handles Unicode backspace and restores terminal on cancellation', async () => {
    const t = terminal();
    const pending = readHidden('Passphrase: ', t);
    t.input.write(Buffer.from('ab🔐\x7fc\r'));
    expect(await pending).toBe('abc');
    const cancelled = readHidden('Passphrase: ', t);
    const rejected = expect(cancelled).rejects.toThrow(/cancelled/);
    t.input.write(Buffer.from('\x03'));
    await rejected;
    expect(t.input.isRaw).toBe(false);
    expect(t.input.listenerCount('data')).toBe(0);
  });
  for (const event of ['end', 'close', 'error']) {
    it(`restores prior raw mode and clears listeners on ${event}`, async () => {
      const t = terminal(); t.input.isRaw = true;
      const pending = readHidden('Passphrase: ', t);
      const rejected = expect(pending).rejects.toThrow(event === 'error' ? /device error/ : /closed/);
      t.input.emit(event, ...(event === 'error' ? [new Error('device error')] : []));
      await rejected;
      expect(t.input.isRaw).toBe(true);
      for (const name of ['data', 'end', 'close', 'error']) expect(t.input.listenerCount(name)).toBe(0);
    });
  }

});
