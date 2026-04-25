import React, { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import Layout from './Layout';
import { User } from '../types/user';

interface PrivateRouteProps {
  children: React.ReactNode;
}

const PrivateRoute: React.FC<PrivateRouteProps> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<User | undefined>(undefined);

  useEffect(() => {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      try {
        const userData = JSON.parse(userStr);
        setCurrentUser(userData);
      } catch (error) {
        console.error('Error parsing user data:', error);
      }
    }
  }, []);

  if (!localStorage.getItem('token')) {
    return <Navigate to="/login" replace />;
  }

  return <Layout user={currentUser}>{children}</Layout>;
};

export default PrivateRoute; 