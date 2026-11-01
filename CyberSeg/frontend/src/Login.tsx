import { FormEvent, useState } from 'react';
import { Session, postJson } from './api';

export function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [user, setUser] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      onLogin(await postJson<Session>('/api/auth/login', { user, password }));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'No se pudo iniciar sesión.');
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  return <main className="login">
    <form onSubmit={submit} className="panel">
      <span className="brand">CYBERSEG</span>
      <h1>Iniciar sesión</h1>
      <label>Usuario<input value={user} onChange={(event) => setUser(event.target.value)} autoComplete="username" required /></label>
      <label>Contraseña<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required autoFocus /></label>
      {error && <p className="error">{error}</p>}
      <button type="submit" disabled={busy}>{busy ? 'Comprobando…' : 'Entrar'}</button>
      <p className="muted small">Tras 5 intentos fallidos el acceso se bloquea 15 minutos.</p>
    </form>
  </main>;
}
