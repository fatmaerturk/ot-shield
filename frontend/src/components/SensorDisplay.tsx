import React, { useState, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale
} from 'chart.js';
import 'chartjs-adapter-date-fns';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale
);

interface SensorData {
  temperature: number;
  humidity: number;
  pressure: number;
  timestamp: number;
}

const SensorDisplay: React.FC = () => {
  const [sensorData, setSensorData] = useState<SensorData[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [retryCount, setRetryCount] = useState(0);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const response = await fetch('http://localhost:8081/api/sensors/data', {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
          },
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data: SensorData = await response.json();
        
        // Debug: Log the received data
        console.log('Received sensor data:', data);
        
        // Validate timestamp to prevent extreme values
        const currentTime = Date.now();
        const maxTimeDiff = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
        
        if (Math.abs(data.timestamp - currentTime) > maxTimeDiff) {
          // If timestamp is too far from current time, use current time
          data.timestamp = currentTime;
        }
        
        // Ensure all required fields exist
        if (data.pressure === undefined || data.pressure === null) {
          console.warn('Pressure data is missing, using default value');
          data.pressure = 1013.25; // Default atmospheric pressure
        }
        
        setSensorData(prevData => {
          const newData = [...prevData, data];
          // Keep last 30 data points
          return newData.slice(-30);
        });
        setError(null);
      } catch (err) {
        console.error('Error fetching sensor data:', err);
        setError(err instanceof Error ? err.message : 'Failed to fetch sensor data');
        // Increment retry count only if we're not already at max retries
        if (retryCount < 3) {
          setRetryCount(prev => prev + 1);
        }
      } finally {
        setLoading(false);
      }
    };

    // Initial fetch
    fetchData();

    // Set up polling interval if we haven't exceeded retry count
    let interval: NodeJS.Timeout | null = null;
    if (retryCount < 3) {
      interval = setInterval(fetchData, 1000);
    }

    // Cleanup
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [retryCount]);

  const chartOptions = {
    responsive: true,
    animation: {
      duration: 0 // Disable animation for better performance
    },
    scales: {
      x: {
        type: 'time' as const,
        time: {
          unit: 'minute' as const,
          displayFormats: {
            minute: 'HH:mm'
          },
          stepSize: 5
        },
        title: {
          display: true,
          text: 'Time'
        },
        ticks: {
          maxTicksLimit: 10
        }
      },
      y: {
        beginAtZero: false,
        title: {
          display: true,
          text: 'Value'
        }
      }
    },
    plugins: {
      legend: {
        position: 'top' as const
      }
    }
  };

  const chartData = {
    datasets: [
      {
        label: 'Temperature (°C)',
        data: sensorData.map(d => ({ x: d.timestamp, y: d.temperature })),
        borderColor: 'rgb(255, 99, 132)',
        backgroundColor: 'rgba(255, 99, 132, 0.5)',
      },
      {
        label: 'Humidity (%)',
        data: sensorData.map(d => ({ x: d.timestamp, y: d.humidity })),
        borderColor: 'rgb(53, 162, 235)',
        backgroundColor: 'rgba(53, 162, 235, 0.5)',
      },
      {
        label: 'Pressure (hPa)',
        data: sensorData.map(d => ({ x: d.timestamp, y: d.pressure })),
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.5)',
        hidden: true, // Hide by default due to different scale
      },
    ],
  };

  const handleRetry = () => {
    setRetryCount(0); // Reset retry count to restart polling
    setError(null);
  };

  if (loading && sensorData.length === 0) {
    return (
      <div className="bg-white p-4 rounded-lg shadow-md">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
          <span className="ml-2">Loading sensor data...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white p-4 rounded-lg shadow-md">
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative" role="alert">
          <strong className="font-bold">Error: </strong>
          <span className="block sm:inline">{error}</span>
          {retryCount >= 3 && (
            <button
              onClick={handleRetry}
              className="mt-2 bg-red-500 hover:bg-red-600 text-white font-bold py-1 px-4 rounded"
            >
              Retry Connection
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white p-4 rounded-lg shadow-md">
      <h2 className="text-xl font-semibold mb-4">Sensor Data</h2>
      <div className="h-64">
        <Line options={chartOptions} data={chartData} />
      </div>
      <div className="grid grid-cols-3 gap-4 mt-4">
        <div className="bg-pink-100 p-3 rounded-lg">
          <h3 className="text-sm font-medium">Temperature</h3>
          <p className="text-2xl font-bold">{sensorData[sensorData.length - 1]?.temperature || '--'}°C</p>
        </div>
        <div className="bg-blue-100 p-3 rounded-lg">
          <h3 className="text-sm font-medium">Humidity</h3>
          <p className="text-2xl font-bold">{sensorData[sensorData.length - 1]?.humidity || '--'}%</p>
        </div>
        <div className="bg-teal-100 p-3 rounded-lg">
          <h3 className="text-sm font-medium">Pressure</h3>
          <p className="text-2xl font-bold">{sensorData[sensorData.length - 1]?.pressure || '--'} hPa</p>
        </div>
      </div>
    </div>
  );
};

export default SensorDisplay; 