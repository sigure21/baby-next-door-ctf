import net from 'node:net';

function parseOneResponse(buffer) {
  const headerEnd = buffer.indexOf('\r\n\r\n');
  if (headerEnd === -1) return null;
  const lines = buffer.subarray(0, headerEnd).toString('latin1').split('\r\n');
  const statusMatch = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/.exec(lines.shift() ?? '');
  if (!statusMatch) throw new Error('invalid HTTP response status line');

  const headers = {};
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon <= 0) throw new Error('invalid HTTP response header');
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    headers[name] = headers[name] ? `${headers[name]}, ${value}` : value;
  }

  const status = Number.parseInt(statusMatch[1], 10);
  const noBody = status < 200 || status === 204 || status === 304;
  const length = noBody ? 0 : Number.parseInt(headers['content-length'] ?? '', 10);
  if (!noBody && (!Number.isSafeInteger(length) || length < 0 || length > 1024 * 1024)) {
    throw new Error('response lacks a bounded Content-Length');
  }
  const total = headerEnd + 4 + length;
  if (buffer.length < total) return null;
  return {
    consumed: total,
    response: { status, headers, body: buffer.subarray(headerEnd + 4, total) },
  };
}

export class RawHttpConnection {
  constructor(host, port) {
    this.host = host;
    this.port = port;
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.pending = null;
  }

  async connect() {
    if (this.socket) return;
    this.socket = net.createConnection({ host: this.host, port: this.port });
    this.socket.on('data', (chunk) => this.#onData(chunk));
    this.socket.on('error', (error) => this.#fail(error));
    this.socket.on('end', () => this.#fail(new Error('server closed the HTTP/1.1 channel')));
    await new Promise((resolve, reject) => {
      const onError = (error) => reject(error);
      this.socket.once('error', onError);
      this.socket.once('connect', () => {
        this.socket.off('error', onError);
        resolve();
      });
    });
  }

  async exchange(request, timeoutMs = 5000) {
    if (!this.socket) await this.connect();
    if (this.pending) throw new Error('raw exchanges must be sequential');
    const wire = Buffer.isBuffer(request) ? request : Buffer.from(request, 'latin1');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error('HTTP exchange timed out'));
      }, timeoutMs);
      this.pending = { informational: [], resolve, reject, timer };
      this.socket.write(wire);
      this.#drain();
    });
  }

  close() {
    if (this.socket) this.socket.destroy();
    this.socket = null;
  }

  #onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this.#drain();
  }

  #drain() {
    while (this.pending) {
      let parsed;
      try {
        parsed = parseOneResponse(this.buffer);
      } catch (error) {
        this.#fail(error);
        return;
      }
      if (!parsed) return;
      this.buffer = this.buffer.subarray(parsed.consumed);
      if (parsed.response.status < 200) {
        this.pending.informational.push(parsed.response);
        continue;
      }
      const current = this.pending;
      this.pending = null;
      clearTimeout(current.timer);
      current.resolve({ informational: current.informational, final: parsed.response });
    }
  }

  #fail(error) {
    if (this.pending) {
      const current = this.pending;
      this.pending = null;
      clearTimeout(current.timer);
      current.reject(error);
    }
  }
}

export function requestHead(method, target, authority, headers = {}) {
  const lines = [`${method} ${target} HTTP/1.1`, `Host: ${authority}`];
  for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
  return `${lines.join('\r\n')}\r\n\r\n`;
}
