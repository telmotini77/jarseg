import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import App from './App';

describe('Visual Control Center', () => {
  it('renders navigation and the dashboard command surface', () => {
    const html = renderToString(<App />);
    expect(html).toContain('Dashboard');
    expect(html).toContain('Agents');
    expect(html).toContain('Ask JARVIS');
  });
});
