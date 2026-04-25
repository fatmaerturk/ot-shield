import axios from 'axios';

// API response interfaces
interface DeviceAtlasResponse {
  model: string;
  manufacturer: string;
  type: string;
}

interface GSMAResponse {
  model: string;
  manufacturer: string;
  deviceType: string;
}

interface SiemensResponse {
  model: string;
  serialNumber: string;
  productType: string;
}

interface AuthResponse {
  token: string;
  refreshToken?: string;
}

const api = axios.create({
  baseURL: 'http://localhost:8080',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

// Allow very large payloads for PCAP uploads
;(api.defaults as any).maxContentLength = Infinity;
;(api.defaults as any).maxBodyLength = Infinity;

/**
 * Storage key for the currently selected Research bundle. Kept in
 * localStorage so a researcher's workspace persists across browser
 * tabs and reboots. BundleContext writes this on selection.
 */
export const ACTIVE_BUNDLE_STORAGE_KEY = 'otshield.activeBundleId';

// Add request interceptor
api.interceptors.request.use(
  (config: any) => {
    const token = localStorage.getItem('token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    // Inject X-Bundle-Id on every Research endpoint. The bundle itself
    // list/create endpoints don't need it (they are not bundle-scoped);
    // we skip injecting it there to avoid a chicken-and-egg where the
    // initial bundle fetch carries a stale active-id header.
    const url: string | undefined = config.url;
    if (
      url &&
      url.startsWith('/api/research/') &&
      !url.startsWith('/api/research/bundles')
    ) {
      const activeBundle = localStorage.getItem(ACTIVE_BUNDLE_STORAGE_KEY);
      if (activeBundle && config.headers) {
        config.headers['X-Bundle-Id'] = activeBundle;
      }
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Token expired veya geçersiz
      const refreshToken = localStorage.getItem('refreshToken');
      
      if (refreshToken) {
        try {
          // Token yenileme denemesi
          const response = await axios.post<AuthResponse>('http://localhost:8080/api/auth/refresh', {
            refreshToken
          });
          
          if (response.data?.token) {
            localStorage.setItem('token', response.data.token);
            
            // Orijinal isteği yeni token ile tekrar dene
            if (error.config.headers) {
              error.config.headers['Authorization'] = `Bearer ${response.data.token}`;
            }
            return axios(error.config);
          }
        } catch (refreshError) {
          console.error('Token refresh failed:', refreshError);
        }
      }
      
      // Token yenilenemezse logout
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;

// Function to get device model from serial number
export const getDeviceModelFromSerial = async (serialNumber: string, manufacturer: string) => {
  try {
    // First try DeviceAtlas API
    const deviceAtlasResponse = await axios.get<DeviceAtlasResponse>(`https://api.deviceatlas.com/api/v1/device/${serialNumber}`, {
      headers: {
        'Authorization': `Bearer ${process.env.REACT_APP_DEVICEATLAS_API_KEY}`
      }
    });

    if (deviceAtlasResponse.data?.model) {
      return deviceAtlasResponse.data.model;
    }

    // If DeviceAtlas fails, try GSMA Device Database
    const gsmaResponse = await axios.get<GSMAResponse>(`https://api.gsma.com/device/${serialNumber}`, {
      headers: {
        'Authorization': `Bearer ${process.env.REACT_APP_GSMA_API_KEY}`
      }
    });

    if (gsmaResponse.data?.model) {
      return gsmaResponse.data.model;
    }

    // If both fail, try manufacturer-specific API
    if (manufacturer.toLowerCase() === 'siemens') {
      const siemensResponse = await axios.get<SiemensResponse>(`https://support.industry.siemens.com/api/v1/devices/${serialNumber}`);
      if (siemensResponse.data?.model) {
        return siemensResponse.data.model;
      }
    }

    return null;
  } catch (error) {
    console.error('Error fetching device model:', error);
    return null;
  }
}; 