export interface User {
  id: string;
  email: string;
  password: string;
  fullName: string;
  username: string;
  role: string;
  isAdmin?: boolean;
  isSuspended?: boolean;
  isExpired?: boolean;
  groups?: string[];
  source?: string;
}

export interface LoginResponse {
  token: string;
  user: User;
}

export interface ApiResponse {
  data: User | User[];
} 