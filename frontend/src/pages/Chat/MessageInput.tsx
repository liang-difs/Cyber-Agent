import { useState, useRef, useEffect } from 'react';
import { Input, Button, Tooltip, Upload, message, Tag } from 'antd';
import { SendOutlined, DisconnectOutlined, PaperClipOutlined, PauseOutlined, CaretRightOutlined } from '@ant-design/icons';
import { uploadFile } from '../../api/task';

const { TextArea } = Input;

interface Props {
  onSend: (content: string, attachments?: Array<{ path: string; name: string }>) => void | Promise<void>;
  waiting: boolean;
  connected: boolean;
  onStop?: () => void;
  interrupted?: boolean;
  onContinue?: () => void;
}

export default function MessageInput({ onSend, waiting, connected, onStop, interrupted, onContinue }: Props) {
  const [value, setValue] = useState('');
  const [attachedFile, setAttachedFile] = useState<{ path: string; name: string; sizeBytes: number } | null>(null);
  const [uploading, setUploading] = useState(false);
  const ref = useRef<any>(null);

  useEffect(() => {
    if (!waiting) ref.current?.focus();
  }, [waiting]);

  const handleUpload = async (file: File) => {
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (ext !== 'pcap' && ext !== 'pcapng') {
      message.error('仅支持 .pcap 和 .pcapng 文件');
      return false;
    }
    setUploading(true);
    try {
      const resp = await uploadFile(file);
      setAttachedFile({ path: resp.file_path, name: resp.filename, sizeBytes: resp.size_bytes });
      message.success(`已附加文件: ${resp.filename}`);
    } catch (err: any) {
      message.error(err.response?.data?.detail || '文件上传失败');
    } finally {
      setUploading(false);
    }
    return false;
  };

  const handleSend = () => {
    const trimmed = value.trim();
    if ((!trimmed && !attachedFile) || waiting || !connected) return;

    let content = trimmed;
    const attachments = attachedFile ? [{ path: attachedFile.path, name: attachedFile.name }] : undefined;
    if (attachedFile) {
      content = trimmed
        ? `${trimmed}\n\n[附件: ${attachedFile.name}]`
        : `请分析这个pcap文件的网络流量:\n[附件: ${attachedFile.name}]`;
      setAttachedFile(null);
    }

    onSend(content, attachments);
    setValue('');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const sendDisabled = waiting || !connected || (!value.trim() && !attachedFile);
  const fileSizeText = attachedFile
    ? attachedFile.sizeBytes >= 1024 * 1024
      ? `${(attachedFile.sizeBytes / 1024 / 1024).toFixed(1)} MB`
      : `${Math.max(1, Math.round(attachedFile.sizeBytes / 1024))} KB`
    : '';

  return (
    <div className="chat-composer">
      {attachedFile && (
        <div className="chat-attachment-row">
          <Tag
            closable
            onClose={() => setAttachedFile(null)}
            icon={<PaperClipOutlined />}
            color="blue"
            className="chat-attachment-tag"
          >
            {attachedFile.name} · {fileSizeText}
          </Tag>
        </div>
      )}

      {/* Interrupted banner */}
      {interrupted && (
        <div className="chat-interrupt-banner">
          <span>生成已被中断</span>
          <Button
            size="small"
            type="link"
            icon={<CaretRightOutlined />}
            onClick={onContinue}
            className="chat-interrupt-continue"
          >
            继续生成
          </Button>
        </div>
      )}

      <div className="chat-composer-box">
        <Upload
          accept=".pcap,.pcapng"
          showUploadList={false}
          beforeUpload={handleUpload}
          disabled={uploading || waiting}
        >
          <Tooltip title="附加 pcap 文件">
            <Button
              icon={<PaperClipOutlined />}
              loading={uploading}
              disabled={waiting}
              className="chat-composer-action"
            />
          </Tooltip>
        </Upload>
        <TextArea
          ref={ref}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={
            connected
              ? attachedFile
                ? '添加描述（可选），Enter 发送...'
                : '输入消息... (Enter 发送, Shift+Enter 换行)'
              : '正在连接服务器...'
          }
          autoSize={{ minRows: 1, maxRows: 4 }}
          disabled={waiting}
          className="chat-composer-input"
        />
        {waiting ? (
          <Tooltip title="停止生成">
            <Button
              danger
              icon={<PauseOutlined />}
              onClick={onStop}
              className="chat-composer-action chat-composer-stop"
            />
          </Tooltip>
        ) : (
          <Tooltip title={!connected ? '未连接到服务器' : undefined}>
            <Button
              type="primary"
              icon={connected ? <SendOutlined /> : <DisconnectOutlined />}
              onClick={handleSend}
              disabled={sendDisabled}
              className="chat-composer-action"
            />
          </Tooltip>
        )}
      </div>
    </div>
  );
}
