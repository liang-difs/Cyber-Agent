import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Divider, Space, Spin, Tag, Typography, message } from 'antd';
import { CheckOutlined, ReloadOutlined, SwapOutlined } from '@ant-design/icons';
import { getModelPresets, switchLLMModel, type LLMCurrentConfig, type ModelPreset } from '../../api/monitor';

type PresetKey = 'deepseek';

interface Props {
  variant?: 'inline' | 'panel';
  editable?: boolean;
  onSwitched?: (preset: PresetKey, config: LLMCurrentConfig) => void;
}

const PRESET_ORDER: PresetKey[] = ['deepseek'];

function resolvePreset(current?: LLMCurrentConfig | null): PresetKey | '' {
  if (!current) return '';
  const model = (current.model || '').toLowerCase();
  const providerHint = (current.provider_hint || '').toLowerCase();

  if (model.includes('deepseek') || providerHint === 'deepseek') {
    return 'deepseek';
  }
  return '';
}

function presetLabel(preset: PresetKey, presets: Record<string, ModelPreset>) {
  return presets[preset]?.label || 'DeepSeek API';
}

function resolveAuthHint(current?: LLMCurrentConfig | null): { label: string; color: string } | null {
  if (!current?.auth || Object.keys(current.auth).length === 0) return null;

  const model = (current.model || '').toLowerCase();
  const baseUrl = (current.base_url || '').toLowerCase();
  const providerHint = (current.provider_hint || '').toLowerCase();
  const isDeepSeek = model.includes('deepseek') || providerHint === 'deepseek';
  const isOpenAICompatible = model.includes('qwen') || baseUrl.includes('8001') || providerHint === 'openai';

  if (isDeepSeek) {
    return current.auth['deepseek_api_key']
      ? { label: 'DeepSeek key 已配置', color: 'green' }
      : { label: 'DeepSeek key 未配置', color: 'orange' };
  }

  if (isOpenAICompatible) {
    return current.auth['openai_api_key']
      ? { label: 'OpenAI 兼容 key 已配置', color: 'green' }
      : { label: 'OpenAI 兼容 key 未配置', color: 'orange' };
  }

  return current.auth['openai_api_key']
    ? { label: 'OpenAI 兼容 key 已配置', color: 'green' }
    : { label: 'OpenAI 兼容 key 未配置', color: 'orange' };
}

export default function LLMModelSwitcher({ variant = 'inline', editable = true, onSwitched }: Props) {
  const [presets, setPresets] = useState<Record<string, ModelPreset>>({});
  const [current, setCurrent] = useState<LLMCurrentConfig | null>(null);
  const [currentPreset, setCurrentPreset] = useState<PresetKey | ''>('');
  const [loading, setLoading] = useState(false);
  const [switching, setSwitching] = useState(false);

  const fetchState = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await getModelPresets();
      setPresets(resp?.presets && typeof resp.presets === 'object' ? resp.presets : {});
      setCurrent(resp?.current || null);
      const nextPreset = resolvePreset(resp?.current);
      setCurrentPreset(nextPreset);
      return { current: resp?.current || null, preset: nextPreset };
    } catch {
      return { current: null, preset: '' as PresetKey | '' };
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchState();
    const timer = window.setInterval(fetchState, 30000);
    return () => window.clearInterval(timer);
  }, [fetchState]);

  const activeLabel = useMemo(() => {
    if (currentPreset) {
      return presetLabel(currentPreset, presets);
    }
    return current?.model || '未识别模型';
  }, [currentPreset, current, presets]);

  const handleSwitch = async (preset: PresetKey) => {
    if (switching || preset === currentPreset) return;
    setSwitching(true);
    try {
      await switchLLMModel(preset);
      const refreshed = await fetchState();
      message.success(`已切换到 ${presetLabel(preset, presets)}`);
      if (refreshed.current) {
        onSwitched?.(preset, refreshed.current);
      }
    } catch (err: any) {
      message.error(err?.response?.data?.detail || '切换失败');
    } finally {
      setSwitching(false);
    }
  };

  const buttons = PRESET_ORDER.map((preset) => {
    const active = preset === currentPreset;
    return (
      <Button
        key={preset}
        type={active ? 'primary' : 'default'}
        icon={active ? <CheckOutlined /> : <SwapOutlined />}
        loading={editable && switching && active}
        disabled={!editable || switching || active}
        onClick={() => void handleSwitch(preset)}
        size="small"
      >
        {presetLabel(preset, presets)}
      </Button>
    );
  });

  const authHint = resolveAuthHint(current);

  if (variant === 'panel') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <Space wrap align="center" style={{ justifyContent: 'space-between', width: '100%' }}>
          <Space wrap align="center">
            <Tag color="blue" style={{ margin: 0 }}>
              当前后端
            </Tag>
            {loading ? <Spin size="small" /> : <Typography.Text strong>{activeLabel}</Typography.Text>}
            {current?.base_url && current.base_url !== 'api' && (
              <Typography.Text type="secondary" ellipsis style={{ maxWidth: 340 }}>
                {current.base_url}
              </Typography.Text>
            )}
            {authHint && <Tag color={authHint.color}>{authHint.label}</Tag>}
          </Space>
          <Button icon={<ReloadOutlined />} onClick={() => void fetchState()} loading={loading} size="small">
            刷新
          </Button>
        </Space>

        <Space wrap>
          {editable ? buttons : <Tag color="default" style={{ margin: 0 }}>仅管理员可切换</Tag>}
        </Space>

        <Divider style={{ margin: '4px 0 0' }} />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          切换后仅影响当前运行中的外部 API 路由；重启后仍以 .env 配置为准。
        </Typography.Text>
      </div>
    );
  }

  return (
    <Space wrap align="center">
      <Tag color="blue" style={{ margin: 0 }}>
        {loading ? '读取模型状态中' : `当前：${activeLabel}`}
      </Tag>
      {editable ? buttons : <Tag color="default" style={{ margin: 0 }}>仅管理员可切换</Tag>}
    </Space>
  );
}
