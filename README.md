# Log Anomaly Detection using Retrieval-Augmented Generation

## Overview
This project implements a **Retrieval-Augmented Generation (RAG)** system designed to detect anomalies in Sysmon security logs. By combining semantic search (SentenceTransformers) with generative AI (Google Gemini or Local LLM), the system can identify malicious activity by comparing new logs against a "Knowledge Base" of known-normal behavior.

The framework supports three modes:
1.  **Standard Mode (`RAG_project.py`)**: Direct embedding of raw logs.
2.  **Enhanced Mode (`RAG_project_enhanced.py`)**: Adds canonicalization (cleaning GUIDs, user paths) and structured templates to reduce noise.
3.  **Sequence Mode (`RAG_project_sequence.py`)**: Analyzes sliding windows of logs (time-series) to detect attack patterns and context-dependent anomalies.

## Prerequisites & Setup

### Environment
*   **Python Version**: Python 3.8+
*   **OS**: Windows, Linux, or macOS (Windows preferred for Sysmon log native formats)

### Dependencies
Install the required packages using `pip`:

```bash
pip install -r requirements.txt
```
*(Contains: `pandas`, `numpy`, `sentence-transformers`, `torch`, `scikit-learn`, `httpx`, `google-genai`, `requests`)*

### API Configuration
To use the Google Gemini models, you must set an API key:

*   **PowerShell**: `$env:GEMINI_API_KEY='your_key_here'`
*   **CMD**: `set GEMINI_API_KEY=your_key_here`
*   **Mac/Linux**: `export GEMINI_API_KEY='your_key_here'`

*Note: For `evaluation_local.py`, a local LLM server (e.g., Ollama running `gemma3:4b` at `localhost:11434`) is required.*

## Usage

### 1. Standard Evaluation
Run the baseline model on a sample of the test set:
```bash
python evaluation.py
```

### 2. Enhanced Evaluation (Recommended)
Uses canonicalization to improve matching accuracy:
```bash
python evaluation.py --enhanced
```

### 3. Sequence Evaluation
Detects anomalies in chains of 5 events (Sliding Window):
```bash
python evaluation.py --sequence
```

### 4. Local LLM Evaluation
Run the evaluation using a local LLM (e.g., Ollama) instead of Gemini API:
```bash
python evaluation_local.py --enhanced --sample_size 50
```

### Common Flags
*   `--sample_size N`: Number of logs to evaluate (Default: 50).
*   `--dry_run`: Generate prompts and log them without making API calls.

## Hyperparameters

| Parameter | Value | Description |
| :--- | :--- | :--- |
| **Embedding Model** | `all-MiniLM-L6-v2` | Lightweight, efficient sentence transformer for vectorizing logs. |
| **LLM Model (Cloud)**| `gemini-2.5-flash-lite` | Google's efficient flash model for low-latency classification. |
| **LLM Model (Local)**| `gemma3:4b` | Quantized local model used in `evaluation_local.py`. |
| **Window Size** | `5` | (Sequence Mode) Number of consecutive logs grouped into one sequence. |
| **Top-K Retrieval** | `5` | Number of similar references retrieved from the Knowledge Base. |
| **Distance Metric** | `Cosine` | Metric used for vector similarity. |
| **Rate Limit (RPM)** | `60` | Requests Per Minute limit to avoid API throttling. |
| **Train/Test Split**| `80/20` | Split ratio for building the Knowledge Base vs. Evaluation. |

## Experiment Results (Local LLM, gemma3:4b)

*(Preliminary results based on sample runs. Metrics may vary based on random seed and local model performance.)*

| Mode | Precision | Recall | F1 Score | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Standard** | 0.00 | 0.00 | 0.00 | Baseline method failed to detect anomalies in this sample set (possibly due to hash/ID mismatches). |
| **Enhanced** | 1.00 | 0.12 | 0.21 | Perfect precision but very low recall. Canonicalization reduced FP, but the model became too conservative. |
| **Sequence** | 0.57 | 0.96 | 0.71 | **Best Recall**. Sequence context helps identify attacks effectively, though with some False Positives. |

## Project Structure

*   `sysmon/`: Directory containing `benign` and `mal` log subdirectories.
*   `knowledge_base*.pkl`: Serialized Vector Database files (Normal logs).
*   `prompt_log.txt`: Log file storing generated prompts from `evaluation.py`.
*   `llm_local_interaction_log.txt`: Log file for Local LLM prompts and responses from `evaluation_local.py`.
*   `RAG_project*.py`: Core logic files for different modes (Standard, Enhanced, Sequence).
*   `evaluation.py`: Main script for Google Gemini API evaluation.
*   `evaluation_local.py`: Script for Local LLM (Ollama) evaluation.
