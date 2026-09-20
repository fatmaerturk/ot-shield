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

  // Backend WebSocket streams. Match the SPECIFIC backend paths only, never
  // bare "/ws" - webpack-dev-server's own hot-reload socket lives at "/ws", and
  // proxying that to the backend causes a 404/403 reconnect loop. In prod nginx
  // proxies all of /ws/ (there is no HMR socket there).
  app.use(
    createProxyMiddleware(['/ws/threats', '/ws/decoy', '/ws/deception'], {
      target,
      changeOrigin: true,
      ws: true,
      logLevel: 'warn',
    })
  );

  // Console proxy
  app.use(
    createProxyMiddleware(['/h2-console'], {
      target,
      changeOrigin: true,
    })
  );
};
