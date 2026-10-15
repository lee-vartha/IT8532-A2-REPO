# SHREDR AI

SHREDR AI is an AI-assisted malware triage and incident reporting prototype developed for IT8532 Advanced Artificial Intelligence and Machine Learning.

The system combines a conventional XGBoost classifier, a fine-tuned Qwen language model, OpenClaw orchestration and Gitea incident reporting.

## Purpose

SHREDR AI is designed to assist an IT or security analyst with the initial triage of suspicious executable files.

The current prototype accepts pre-extracted structured executable features. It does not directly accept or execute executable files.

The XGBoost classifier determines whether the supplied feature record is likely to represent benign or malicious software. The fine-tuned language model converts the classifier evidence into an analyst-readable triage report.

## Architecture

The deployed system uses three containers:

- **CT200 - Inference Server**
  - XGBoost prediction API
  - Fine-tuned Qwen2.5-1.5B model
  - Base Qwen model for comparison
  - llama.cpp / MultiShim model routing

- **CT201 - OpenClaw**
  - SHREDR OpenClaw skill
  - Prediction integration
  - Deterministic guardrails
  - Triage workflow
  - Gitea integration

- **CT202 - Gitea**
  - SHREDR incident repository
  - Auditable incident issues

The simplified workflow is:

Structured Features
→ OpenClaw
→ XGBoost Prediction API
→ Guardrail Check
→ Fine-tuned Qwen Report
→ Gitea Incident

If a guardrail is triggered, the workflow stops and requires manual review.

## Repository Structure

- `api/` - FastAPI prediction service and example requests
- `data/` - structured malware classification dataset
- `models/` - trained XGBoost model, feature list and model configuration
- `notebooks/` - XGBoost data preparation, training and evaluation
- `llm/data/` - SHREDR instruction dataset and train/validation/test splits
- `llm/notebooks/` - language-model dataset preparation and fine-tuning notebooks
- `llm/models/` - model artefacts
- `openclaw/` - OpenClaw skill and deterministic orchestration scripts
- `IT8532 - Emily Vartha A2 - 2026.docx` - Final assessment report and implementation evidence

## Machine Learning Model

The malware classifier uses XGBoost.

The final model uses 242 numerical features and returns:

- benign or malware classification
- malware probability
- operational decision threshold

The operational malware threshold is 0.10.

## Language Model

The reporting model is based on Qwen2.5-1.5B-Instruct and was fine-tuned using Unsloth and LoRA/QLoRA.

The model was trained to generate a structured SHREDR report containing:

- Risk assessment
- Evidence interpretation
- Recommended action

The language model does not determine the malware classification. It reports the evidence produced by the XGBoost classifier.

## Guardrails

SHREDR includes deterministic controls for failure and uncertainty.

Examples include:

- incomplete prediction input stops the workflow
- prediction service failure requires manual review
- predictions within ±0.02 of the decision threshold require human review
- malformed numerical input is rejected

SHREDR must not execute, delete, modify, upload, move or quarantine a suspicious file, or perform endpoint remediation, without explicit human approval.

The prototype contains no tool or code path for these destructive actions.

## Large Model Files

Large GGUF model files are not included in the Git repository because of their size. The project documentation contains evidence of GGUF export and deployment. The trained LoRA adapter is included as 'llm/models/shredr_qwen_lora_adapter.zip'

## Important Limitations

SHREDR is an educational prototype and is not a production antivirus system.

The current system:

- accepts pre-extracted features rather than executable files
- has not been validated against an independent contemporary malware dataset
- requires human review for uncertain predictions
- does not perform automatic malware remediation
- should not be used as the sole basis for a security decision

## Assessment

Developed by Emily Vartha for:

**IT8532 - Advanced Artificial Intelligence and Machine Learning**  
**Assessment 2 - Design and Implementation of an AI Solution**  
**NMIT, 2026**
