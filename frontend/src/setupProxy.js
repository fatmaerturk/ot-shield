/**
 * Dev-only proxy (replaces package.json "proxy").
 * CRA bug: HOST in .env + package.json proxy breaks webpack-dev-server allowedHosts.
 */
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function setupProxy(app) {
  const target = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8080';

  // API proxy - without WS upgrade to avoid stream errors
  app.use(
    createProxyMiddleware(['/api', '/pcap'], {
      target,
      changeOrigin: true,
      logLevel: 'warn',
    })
  );

  // NOTE: Backend WebSocket proxy was on /ws, but that path collides with
  // CRA's own hot-reload WebSocket (webpack-dev-server also uses /ws).
  // Result: infinite 404/403 loop from backend.
  // If/when we need a backend WS stream, expose it under a non-/ws path
  // (e.g. /api/stream) and proxy that here.

  // Console proxy
  app.use(
    createProxyMiddleware(['/h2-console'], {
      target,
      changeOrigin: true,
    })
  );
};
