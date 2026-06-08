import { useMemo, useState } from 'react';
import { Button, Dropdown, Input, List, Modal, Typography, message as antMsg } from 'antd';
import { DeleteOutlined, DownloadOutlined, MoreOutlined, PlusOutlined, EditOutlined } from '@ant-design/icons';
import { useChatStore } from '../../stores/chat';
import { exportChatSession } from '../../api/chat';
import dayjs from 'dayjs';

const { Text } = Typography;

export default function SessionList() {
  const {
    sessions,
    currentSessionId,
    selectSession,
    createSession,
    renameSession,
    deleteSession,
  } = useChatStore();
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameSessionId, setRenameSessionId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [saving, setSaving] = useState(false);

  const renameTarget = useMemo(
    () => sessions.find((session) => session.id === renameSessionId) || null,
    [sessions, renameSessionId],
  );

  const handleOpenRename = (sessionId: string) => {
    const target = sessions.find((session) => session.id === sessionId);
    if (!target) return;
    setRenameSessionId(sessionId);
    setRenameValue(target.title || '');
    setRenameOpen(true);
  };

  const handleRename = async () => {
    if (!renameSessionId) return;
    const title = renameValue.trim();
    if (!title) {
      antMsg.error('标题不能为空');
      return;
    }
    setSaving(true);
    try {
      await renameSession(renameSessionId, title);
      antMsg.success('会话已重命名');
      setRenameOpen(false);
      setRenameSessionId(null);
    } catch (error: any) {
      antMsg.error(error?.response?.data?.detail || '重命名失败');
    } finally {
      setSaving(false);
    }
  };

  const handleExport = async (sessionId: string) => {
    try {
      const payload = await exportChatSession(sessionId);
      const title = payload.session.title || 'chat-session';
      const safeTitle = title.replace(/[\\/:*?"<>|]+/g, '_').slice(0, 80);
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${safeTitle}-${sessionId.slice(0, 8)}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      antMsg.success('已导出会话');
    } catch (error: any) {
      antMsg.error(error?.response?.data?.detail || '导出失败');
    }
  };

  const handleDelete = (sessionId: string) => {
    const wasCurrent = sessionId === currentSessionId;
    Modal.confirm({
      title: '删除会话',
      content: '删除后将清空该会话及其消息，无法恢复。是否继续？',
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        await deleteSession(sessionId);
        if (wasCurrent) {
          const nextSession = sessions.find((session) => session.id !== sessionId);
          if (nextSession) {
            await selectSession(nextSession.id);
          }
        }
        antMsg.success('会话已删除');
      },
    });
  };

  return (
    <div style={{ width: 240, borderRight: '1px solid var(--app-border)', height: '100%', display: 'flex', flexDirection: 'column', background: 'var(--app-surface)' }}>
      <div style={{ padding: 12 }}>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          block
          onClick={() => {
            void createSession().catch(() => antMsg.error('会话创建失败'));
          }}
        >
          新会话
        </Button>
      </div>
      <List
        style={{ flex: 1, overflow: 'auto' }}
        dataSource={sessions}
        renderItem={(session) => (
          <List.Item
            onClick={() => void selectSession(session.id)}
            className={`chat-session-item ${session.id === currentSessionId ? 'chat-session-item-active' : ''}`}
          >
            <div className="chat-session-item-content">
              <div className="chat-session-item-text">
                <Text ellipsis className="chat-session-title">{session.title}</Text>
                <Text type="secondary" ellipsis className="chat-session-meta">
                  {dayjs(session.updatedAt).format('MM-DD HH:mm')}
                </Text>
              </div>
              <Dropdown
                trigger={['click']}
                placement="bottomRight"
                menu={{
                  items: [
                    {
                      key: 'rename',
                      label: 'Rename',
                      icon: <EditOutlined />,
                    },
                    {
                      key: 'export',
                      label: 'Export',
                      icon: <DownloadOutlined />,
                    },
                    {
                      key: 'delete',
                      label: 'Delete',
                      icon: <DeleteOutlined />,
                      danger: true,
                    },
                  ],
                  onClick: ({ key, domEvent }) => {
                    domEvent.preventDefault();
                    domEvent.stopPropagation();
                    if (key === 'rename') {
                      handleOpenRename(session.id);
                    } else if (key === 'export') {
                      void handleExport(session.id);
                    } else if (key === 'delete') {
                      handleDelete(session.id);
                    }
                  },
                }}
              >
                <Button
                  type="text"
                  icon={<MoreOutlined />}
                  className="chat-session-more"
                  onClick={(e) => {
                    e.stopPropagation();
                  }}
                />
              </Dropdown>
            </div>
          </List.Item>
        )}
      />
      <Modal
        title="重命名会话"
        open={renameOpen}
        onOk={() => void handleRename()}
        onCancel={() => {
          setRenameOpen(false);
          setRenameSessionId(null);
        }}
        confirmLoading={saving}
        okText="保存"
        cancelText="取消"
      >
        <Input
          value={renameValue}
          onChange={(e) => setRenameValue(e.target.value)}
          placeholder="请输入会话标题"
          maxLength={256}
          onPressEnter={() => void handleRename()}
          autoFocus
        />
        {renameTarget && (
          <Text type="secondary" style={{ display: 'block', marginTop: 8, fontSize: 12 }}>
            当前会话：{renameTarget.title}
          </Text>
        )}
      </Modal>
    </div>
  );
}
