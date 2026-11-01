// Minimal request/response shapes, so the backend does not need @types/express.
export type HttpRequest = {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  session?: { user: string; role: string };
};

export type HttpResponse = {
  setHeader(name: string, value: string): void;
  status(code: number): HttpResponse;
};

export function cookie(request: HttpRequest, name: string): string | undefined {
  const header = request.headers.cookie;
  const raw = Array.isArray(header) ? header.join('; ') : header || '';
  for (const part of raw.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return decodeURIComponent(value.join('='));
  }
  return undefined;
}

// nginx forwards the browser's address; direct (loopback) callers use the socket.
export function clientAddress(request: HttpRequest): string {
  const forwarded = request.headers['x-real-ip'];
  return (Array.isArray(forwarded) ? forwarded[0] : forwarded) || request.socket?.remoteAddress || 'desconocido';
}
