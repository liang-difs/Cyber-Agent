import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeSanitize from 'rehype-sanitize';
import CveCard from './CveCard';
import CveCatalogCard from './CveCatalogCard';
import IocCard from './IocCard';
import IpCard from './IpCard';

type ResponseType = 'cve' | 'cve_catalog' | 'ioc' | 'ip' | 'markdown';

function detectResponseType(content: string): ResponseType {
  if (/^##\s*CVE\s*\/\s*KEV\s*结构化查询结果/m.test(content)) return 'cve_catalog';
  if (/^##\s+CVE-\d+-\d+/m.test(content)) return 'cve';
  if (/^##\s*IoC\s*分析报告/m.test(content)) return 'ioc';
  if (/^##\s*IP\s*威胁分析报告/m.test(content)) return 'ip';
  return 'markdown';
}

interface Props {
  content: string;
  streaming?: boolean;
  responseType?: ResponseType;
}

export default function ResponseCards({ content, streaming = false, responseType }: Props) {
  // During streaming, content may be incomplete — always use markdown for smooth token display
  if (streaming) {
    return (
      <div className={`markdown-body ${streaming ? 'streaming-cursor' : ''}`}>
        <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]}>{content}</ReactMarkdown>
      </div>
    );
  }

  const type = responseType || detectResponseType(content);

  switch (type) {
    case 'cve':
      return <CveCard content={content} />;
    case 'cve_catalog':
      return <CveCatalogCard content={content} />;
    case 'ioc':
      return <IocCard content={content} />;
    case 'ip':
      return <IpCard content={content} />;
    default:
      return (
        <div className="markdown-body">
          <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]}>{content}</ReactMarkdown>
        </div>
      );
  }
}
