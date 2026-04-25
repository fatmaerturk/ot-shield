import React from 'react';

interface ModernCardProps {
  title?: string;
  icon?: string;
  children: React.ReactNode;
  className?: string;
  borderColor?: 'blue' | 'purple' | 'green' | 'red' | 'orange';
  onClick?: () => void;
}

const ModernCard: React.FC<ModernCardProps> = ({
  title,
  icon,
  children,
  className = '',
  borderColor = 'blue',
  onClick,
}) => {
  const borderColorMap = {
    blue: 'border-l-4 border-l-blue-500',
    purple: 'border-l-4 border-l-purple-500',
    green: 'border-l-4 border-l-green-500',
    red: 'border-l-4 border-l-red-500',
    orange: 'border-l-4 border-l-orange-500',
  };

  return (
    <div
      onClick={onClick}
      className={`bg-white rounded-lg shadow-sm hover:shadow-md transition-all duration-200 p-6 ${borderColorMap[borderColor]} ${
        onClick ? 'cursor-pointer hover:-translate-y-0.5' : ''
      } ${className}`}
    >
      {title && (
        <div className="flex items-center gap-2 mb-4">
          {icon && <span className="text-2xl">{icon}</span>}
          <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
        </div>
      )}
      {children}
    </div>
  );
};

export default ModernCard;
