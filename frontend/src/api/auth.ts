import client from './client';
import type { LoginRequest, LoginResponse } from '../types/api';

export async function login(req: LoginRequest): Promise<LoginResponse> {
  const { data } = await client.post<LoginResponse>('/auth/login', req);
  return data;
}
