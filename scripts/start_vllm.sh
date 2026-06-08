#!/bin/bash
# 启动 vLLM 推理服务 (Qwen3-14B-Instruct)
#
# 前置条件:
#   - 已安装 vLLM: pip install vllm
#   - NVIDIA GPU 可用 (默认使用 GPU 0,1)
#   - 模型权重位于 ../model/Qwen3-14B-Instruct/
#
# 用法:
#   bash scripts/start_vllm.sh
#
# 启动后设置环境变量切换到本地模型:
#   export LLM_BASE_URL=http://localhost:8001/v1
#   export LLM_MODEL=qwen3-14b
#   export OPENAI_API_KEY=EMPTY

MODEL_DIR="${MODEL_DIR:-$(dirname "$0")/../model/Qwen3-14B-Instruct}"
PORT="${VLLM_PORT:-8001}"
TP="${VLLM_TP_SIZE:-2}"
MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-16384}"
GPU_UTIL="${VLLM_GPU_UTIL:-0.90}"
MAX_NUM_SEQS="${VLLM_MAX_NUM_SEQS:-64}"

echo "Starting vLLM server..."
echo "  Model: $MODEL_DIR"
echo "  Port: $PORT"
echo "  Tensor Parallelism: $TP GPUs"
echo "  Max Model Length: $MAX_MODEL_LEN"
echo "  Max Num Seqs: $MAX_NUM_SEQS"
echo "  GPU Memory Utilization: $GPU_UTIL"

python -m vllm.entrypoints.openai.api_server \
    --model "$MODEL_DIR" \
    --tensor-parallel-size "$TP" \
    --max-model-len "$MAX_MODEL_LEN" \
    --max-num-seqs "$MAX_NUM_SEQS" \
    --gpu-memory-utilization "$GPU_UTIL" \
    --port "$PORT" \
    --host 0.0.0.0 \
    --served-model-name qwen3-14b
