# RAG Reindex Playbook

> RAG 重新索引操作手册。

## 适用场景
- Embedding 模型变更
- 文档结构变更
- 索引损坏
- 性能优化需要重新分块

## 步骤

### 1. 备份当前索引
```bash
# ChromaDB 备份
cp -r /data/chroma /data/chroma_backup_$(date +%Y%m%d)

# Elasticsearch 备份
curl -X PUT "localhost:9200/_snapshot/backup/snapshot_$(date +%Y%m%d)"
```

### 2. 创建新 Collection
```python
# 使用新的 embedding 模型或分块策略
from chromadb import Client
client = Client()
new_collection = client.create_collection(
    name="docs_v2",
    metadata={"hnsw:space": "cosine"}
)
```

### 3. 重新索引
```bash
# 运行索引脚本
python scripts/reindex_rag.py \
  --source /data/documents \
  --collection docs_v2 \
  --chunk-size 512 \
  --overlap 50
```

### 4. 验证
```bash
# 运行 RAG 测试
pytest tests/ai_runtime/rag/ -v

# 对比新旧索引的检索质量
python scripts/compare_rag_quality.py \
  --old-collection docs_v1 \
  --new-collection docs_v2
```

### 5. 切换
- 更新 RAG 配置指向新 collection
- 监控首次查询的延迟和质量

## 回滚

如果新索引质量不达标：
1. 恢复旧 collection 配置
2. 删除新 collection
3. 记录失败原因到 `memory/failed_attempts.md`
