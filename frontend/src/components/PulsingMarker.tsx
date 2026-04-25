import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import { useMap } from 'react-leaflet';

interface PulsingMarkerProps {
  position: L.LatLngTuple;
  ip: string;
  count: number;
  protocol: string;
  country?: string;
  city?: string;
}

// Define the pulsing icon configuration with country-based styling
const createPulsingIcon = (country?: string) => {
  const countryClass = country === 'Russia' ? 'russia' : country === 'China' ? 'china' : 'default';
  
  return L.divIcon({
    className: `custom-pulse-icon ${countryClass}`,
    html: `
      <div class="pulsing-dot" data-country="${country || 'Unknown'}"></div>
      <div class="pulsing-ring" data-country="${country || 'Unknown'}"></div>
    `,
    iconSize: [0, 0], // Size is handled by the CSS
  });
};

const PulsingMarker: React.FC<PulsingMarkerProps> = React.memo(({ position, ip, count, protocol, country, city }) => {
  const map = useMap();
  const markerRef = useRef<L.Marker | null>(null);

  useEffect(() => {
    // Create marker if it doesn't exist
    if (!markerRef.current) {
      const icon = createPulsingIcon(country);
      markerRef.current = L.marker(position, { icon }).addTo(map);
    } else {
      // Update position if it changes (though less likely in this scenario)
      markerRef.current.setLatLng(position);
      // Update icon if country changes
      const newIcon = createPulsingIcon(country);
      markerRef.current.setIcon(newIcon);
    }

    // Update popup content with enhanced information
    const locationInfo = country && city ? `${city}, ${country}` : 'Unknown Location';
    const threatLevel = country === 'Russia' ? 'HIGH' : country === 'China' ? 'MEDIUM' : 'LOW';
    const threatClass = country === 'Russia' ? 'threat-level-high' : country === 'China' ? 'threat-level-medium' : '';
    
    const popupContent = `
      <div style="min-width: 220px;">
        <div style="margin-bottom: 8px;">
          <strong>IP Address:</strong> ${ip}<br/>
          <strong>Location:</strong> ${locationInfo}<br/>
          <strong>Attack Count:</strong> ${count}<br/>
          <strong>Protocol:</strong> ${protocol}
        </div>
        <div style="margin-top: 8px;">
          <span class="${threatClass}" style="display: inline-block; margin-right: 8px;">
            Threat Level: ${threatLevel}
          </span>
          <span style="font-size: 0.75rem; color: #666;">
            ${country === 'Russia' ? '🇷🇺' : country === 'China' ? '🇨🇳' : '🌍'} ${country || 'Unknown'}
          </span>
        </div>
      </div>
    `;
    markerRef.current.bindPopup(popupContent);

    // Cleanup: remove marker when component unmounts
    return () => {
      if (markerRef.current) {
        map.removeLayer(markerRef.current);
        markerRef.current = null;
      }
    };
  }, [map, position, ip, count, protocol, country, city]); // Dependencies for effect

  // This component doesn't render anything itself via React, it manages the Leaflet layer directly
  return null; 
});

export default PulsingMarker; 