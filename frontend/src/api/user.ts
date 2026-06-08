import client from './client';
import type { User } from '../types/api';

export interface UserListResponse {
  users: User[];
  total: number;
}

export async function listUsers(params?: { limit?: number; offset?: number }): Promise<UserListResponse> {
  const { data } = await client.get('/users', { params });
  return data;
}

export async function createUser(body: {
  username: string;
  password: string;
  role?: string;
  email?: string;
}): Promise<User> {
  const { data } = await client.post('/users', body);
  return data;
}

export async function updateUser(id: string, body: {
  role?: string;
  email?: string;
  is_active?: boolean;
  password?: string;
}): Promise<User> {
  const { data } = await client.patch(`/users/${id}`, body);
  return data;
}

export async function deleteUser(id: string): Promise<void> {
  await client.delete(`/users/${id}`);
}
