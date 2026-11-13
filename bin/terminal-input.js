'use strict';
const { StringDecoder } = require('node:string_decoder');

/** Read without echo; preserve streaming UTF-8 and restore raw mode on every exit. */
function readHidden(prompt, { input = process.stdin, output = process.stderr } = {}) {
  return new Promise((resolve, reject) => {
    const decoder = new StringDecoder('utf8');
    const previousRawMode = Boolean(input.isRaw);
    let value = '';
    let finished = false;
    const finish = (error) => {
      if (finished) return;
      finished = true;
      input.removeListener('data', onData);
      input.removeListener('error', onError);
      input.removeListener('end', onEnd);
      input.removeListener('close', onEnd);
      input.setRawMode(previousRawMode);
      input.pause();
      output.write('\n');
      if (error) reject(error); else resolve(value);
    };
    const onError = error => finish(error);
    const onEnd = () => finish(new Error('Terminal closed before the passphrase was completed.'));
    const onData = chunk => {
      for (const char of decoder.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))) {
        if (char === '\r' || char === '\n') return finish();
        if (char === '\u0003') return finish(new Error('cancelled'));
        if (char === '\u0004') return finish();
        if (char === '\u007f' || char === '\b') value = Array.from(value).slice(0, -1).join('');
        else if (char >= ' ') value += char;
      }
    };
    output.write(prompt);
    input.setRawMode(true);
    input.on('data', onData);
    input.on('error', onError);
    input.on('end', onEnd);
    input.on('close', onEnd);
    input.resume();
  });
}
module.exports = { readHidden };
