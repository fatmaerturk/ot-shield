import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, Legend, ResponsiveContainer } from 'recharts';

interface Iec104Event {
  timestamp: string;
  type: string;
  value: string;
  description: string;
}

const numericTypes = ['Voltage', 'Current', 'Frequency', 'PowerFactor'];

const IEC104Events: React.FC = () => {
  const [events, setEvents] = useState<Iec104Event[]>([]);

  useEffect(() => {
    axios.get<Iec104Event[]>('http://localhost:8081/api/iec104/events')
      .then(res => setEvents(res.data))
      .catch(err => console.error(err));
  }, []);

  // Grafik için sadece numeric değerleri filtrele
  const chartData = events
    .filter(evt => numericTypes.includes(evt.type) && !isNaN(Number(evt.value)))
    .map(evt => ({
      timestamp: evt.timestamp,
      type: evt.type,
      value: Number(evt.value)
    }));

  return (
    <div style={{ margin: '2rem 0' }}>
      <h2>IEC 104 Olayları</h2>
      <div style={{ maxHeight: 300, overflowY: 'auto', marginBottom: 24 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th>Zaman</th>
              <th>Tip</th>
              <th>Değer</th>
              <th>Açıklama</th>
            </tr>
          </thead>
          <tbody>
            {events.map((evt, i) => (
              <tr key={i}>
                <td>{evt.timestamp}</td>
                <td>{evt.type}</td>
                <td>{evt.value}</td>
                <td>{evt.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h3>Son Ölçümler (Grafik)</h3>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={chartData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="timestamp" tickFormatter={str => str.slice(11,19)} minTickGap={30} />
          <YAxis />
          <Tooltip />
          <Legend />
          {numericTypes.map(type => (
            <Line key={type} type="monotone" dataKey={d => d.type === type ? d.value : null} name={type} stroke={
              type === 'Voltage' ? '#8884d8' :
              type === 'Current' ? '#82ca9d' :
              type === 'Frequency' ? '#ffc658' :
              '#ff7300'
            } dot={false} isAnimationActive={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default IEC104Events; 