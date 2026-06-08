import axios from 'axios';
import client from './client';
import type { HealthResponse } from '../types/api';

export async function getHealth(): Promise<{ status: string; timestamp: string; version: string }> {
  const { data } = await axios.get('/health');
  return data;
}

export async function getDetailedHealth(): Promise<HealthResponse> {
  const { data } = await axios.get('/health/detailed');
  return data;
}

export interface ModelPreset {
  provider?: string;
  model: string;
  base_url: string;
  label: string;
}

export interface LLMCurrentConfig {
  model: string;
  base_url: string;
  provider_hint?: string;
  auth?: Record<string, boolean>;
}

export async function getModelPresets(): Promise<{ current: LLMCurrentConfig; presets: Record<string, ModelPreset> }> {
  const { data } = await client.get('/llm/models');
  return data;
}

export async function switchLLMModel(preset: string): Promise<{ ok: boolean; config: Record<string, any> }> {
  const { data } = await client.post('/llm/switch', { preset });
  return data;
}
