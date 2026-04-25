// Modern OTShield Theme Configuration
export const theme = {
  colors: {
    primary: '#3b82f6',      // Blue
    secondary: '#8b5cf6',    // Purple
    success: '#10b981',      // Green
    warning: '#f59e0b',      // Orange
    danger: '#ef4444',       // Red
    background: '#f9fafb',   // Gray-50
    surface: '#ffffff',      // White
    border: '#e5e7eb',       // Gray-200
    text: {
      primary: '#111827',    // Gray-900
      secondary: '#6b7280',  // Gray-500
      tertiary: '#9ca3af',   // Gray-400
    },
  },
  spacing: {
    xs: '0.25rem',
    sm: '0.5rem',
    md: '1rem',
    lg: '1.5rem',
    xl: '2rem',
    '2xl': '3rem',
  },
  borderRadius: {
    sm: '0.375rem',
    md: '0.5rem',
    lg: '0.75rem',
  },
  shadows: {
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
  },
};

// Reusable className builders
export const classNames = {
  card: 'bg-white rounded-lg shadow-sm hover:shadow-md transition-all duration-200 p-6',
  cardClickable: 'bg-white rounded-lg shadow-sm hover:shadow-md transition-all duration-200 p-6 cursor-pointer hover:-translate-y-0.5',
  button: {
    primary: 'bg-blue-500 text-white hover:bg-blue-600 px-4 py-2 rounded-lg font-medium transition-colors',
    secondary: 'bg-gray-200 text-gray-900 hover:bg-gray-300 px-4 py-2 rounded-lg font-medium transition-colors',
    danger: 'bg-red-500 text-white hover:bg-red-600 px-4 py-2 rounded-lg font-medium transition-colors',
  },
  input: 'w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-colors',
  badge: {
    primary: 'inline-block bg-blue-100 text-blue-700 px-3 py-1 rounded-full text-sm font-medium',
    success: 'inline-block bg-green-100 text-green-700 px-3 py-1 rounded-full text-sm font-medium',
    warning: 'inline-block bg-yellow-100 text-yellow-700 px-3 py-1 rounded-full text-sm font-medium',
    danger: 'inline-block bg-red-100 text-red-700 px-3 py-1 rounded-full text-sm font-medium',
  },
};

// Font sizes
export const fontSize = {
  xs: ['0.75rem', { lineHeight: '1rem' }],
  sm: ['0.875rem', { lineHeight: '1.25rem' }],
  base: ['1rem', { lineHeight: '1.5rem' }],
  lg: ['1.125rem', { lineHeight: '1.75rem' }],
  xl: ['1.25rem', { lineHeight: '1.75rem' }],
  '2xl': ['1.5rem', { lineHeight: '2rem' }],
  '3xl': ['1.875rem', { lineHeight: '2.25rem' }],
};
