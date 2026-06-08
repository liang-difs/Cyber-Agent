import { Drawer, Descriptions, Tag, Typography, Grid } from 'antd';
import type { CveItem } from '../../types/api';
import { SEVERITY_TAG_COLORS as severityColors } from '../../constants/severity';

const { Paragraph } = Typography;
const { useBreakpoint } = Grid;

interface Props {
  cve: CveItem | null;
  open: boolean;
  onClose: () => void;
}

export default function CveDetail({ cve, open, onClose }: Props) {
  const screens = useBreakpoint();
  if (!cve) return null;

  return (
    <Drawer
      title={cve.cve_id}
      open={open}
      onClose={onClose}
      width={screens.md ? 560 : '100%'}
    >
      <Descriptions column={1} bordered size="small">
        <Descriptions.Item label="CVE ID">{cve.cve_id}</Descriptions.Item>
        <Descriptions.Item label="严重程度">
          <Tag color={severityColors[cve.severity] || 'default'}>{cve.severity}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="CVSS 分数">{cve.cvss_score}</Descriptions.Item>
        <Descriptions.Item label="发布日期">{cve.published || 'N/A'}</Descriptions.Item>
        <Descriptions.Item label="描述">
          <Paragraph style={{ margin: 0 }}>{cve.description || 'N/A'}</Paragraph>
        </Descriptions.Item>
      </Descriptions>
    </Drawer>
  );
}
