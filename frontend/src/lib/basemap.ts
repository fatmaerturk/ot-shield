// CARTO basemap tiles.
//
// As of August 2026 CARTO enforces an API key on basemaps.cartocdn.com. Without
// a key the tiles come back stamped "API KEY REQUIRED". A key is free, needs no
// CARTO account, and takes a minute to request at:
//     https://carto.com/basemaps/apikey/
// Put it in frontend/.env as REACT_APP_CARTO_KEY=your_key and restart the dev
// server (CRA only reads .env at start-up).
const CARTO_KEY = (process.env.REACT_APP_CARTO_KEY ?? '').trim();

// Dark ("dark_all") raster basemap, retina-aware ({r}). The key is appended as
// ?key=... (CARTO's parameter name is `key`, not `api_key`).
export const CARTO_DARK_URL =
  'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png' +
  (CARTO_KEY ? `?key=${CARTO_KEY}` : '');

export const CARTO_SUBDOMAINS = ['a', 'b', 'c', 'd'];

export const CARTO_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/">CARTO</a>';
