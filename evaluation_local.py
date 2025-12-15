import asyncio
import argparse
import pandas as pd
from pathlib import Path
import importlib.util
import sys
import os
import requests
import json
import types

# Helper to import the RAG system dynamically
def import_rag_system(file_path):
    spec = importlib.util.spec_from_file_location("RAG_project", file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["RAG_project"] = module
    spec.loader.exec_module(module)
    if hasattr(module, 'RAGLogSystem'):
        return module.RAGLogSystem
    return module.RAGSequenceSystem

async def _call_local_llm_api_patch(self, payload):
    """
    Patched method to call local LLM API instead of Gemini.
    """
    # Extract prompt from Gemini payload structure
    try:
        # Gemini payload structure:
        # contents -> parts -> text (User Query)
        # systemInstruction -> parts -> text (System Prompt)
        
        user_query = ""
        if 'contents' in payload and payload['contents']:
            user_query = payload['contents'][0]['parts'][0]['text']
            
        system_prompt = ""
        if 'systemInstruction' in payload and payload.get('systemInstruction'):
            system_prompt = payload['systemInstruction']['parts'][0]['text']
            
        # Combine into a single prompt for the local model
        # You might want to format this according to the specific model's template if it's chatting,
        # but simple concatenation handles instructions well for general purpose.
        full_prompt = f"{system_prompt}\n\n{user_query}" if system_prompt else user_query
        
        # Local LLM Endpoint
        url = "http://localhost:11434/api/generate"
        
        # Request Data
        data = {
            "model": "gemma3:4b", # Hardcoded as per user request example
            "prompt": full_prompt,
            "stream": False,
            "format": "json" # Request JSON output to match expected return type
        }
        
        print(f" [Local LLM] Calling {url} with model {data['model']}...")
        
        # Run synchronous request in executor to avoid blocking the async loop
        loop = asyncio.get_event_loop()
        def run_request():
            return requests.post(url, json=data)
            
        response = await loop.run_in_executor(None, run_request)
        response.raise_for_status()
        
        result_json = response.json()
        
        # The user's example: print(response.json()['response'])
        # So the text is in 'response' key.
        response_text = result_json.get('response', '')

        # --- LOG PROMPT & RESPONSE ---
        try:
            with open("llm_local_interaction_log.txt", "a", encoding="utf-8") as f:
                f.write("\n" + "="*50 + "\n")
                f.write(" [PROMPT]\n")
                f.write(full_prompt + "\n")
                f.write("-" * 20 + "\n")
                f.write(" [RESPONSE]\n")
                f.write(response_text + "\n")
                f.write("="*50 + "\n\n")
        except Exception as log_err:
            print(f"Warning: Failed to log interaction: {log_err}")
        # -----------------------------
        
        # Return in the structure expected by detect_anomaly:
        # {'candidates': [{'content': {'parts': [{'text': ...}]}}]}
        return {
            'candidates': [
                {'content': {'parts': [{'text': response_text}]}}
            ]
        }
        
    except Exception as e:
        print(f" [Local LLM] Error: {e}")
        return None

async def main():
    parser = argparse.ArgumentParser(description="Eval Script (Local LLM)")
    parser.add_argument("--sample_size", type=int, default=50, help="Number of logs to test")
    parser.add_argument("--dry_run", action="store_true", help="Enable dry run")
    parser.add_argument("--enhanced", action="store_true", help="Use enhanced RAG system (canonicalization + structured)")
    parser.add_argument("--sequence", action="store_true", help="Use Sequence-based RAG system (Sliding Window)")
    args = parser.parse_args()

    # Priority: Sequence > Enhanced > Normal
    if args.sequence:
        version_str = "SEQUENCE"
    elif args.enhanced:
        version_str = "ENHANCED"
    else:
        version_str = "NORMAL"
    
    print(f"--- Small Sample Evaluation (Version={version_str}, N={args.sample_size}, DryRun={args.dry_run}) ---")
    print("--- Using LOCAL LLM (gemma3:4b) ---")
    
    # Clear previous prompt log
    if os.path.exists("prompt_log.txt"):
        try:
            os.remove("prompt_log.txt")
            print("Cleared previous prompt_log.txt")
        except Exception as e:
            print(f"Warning: Could not clear prompt_log.txt: {e}")
    
    # 1. Initialize System
    if args.sequence:
        project_path = "./RAG_project_sequence.py"
        kb_path = "knowledge_base_sequence.pkl"
    elif args.enhanced:
        project_path = "./RAG_project_enhanced.py"
        kb_path = "knowledge_base_enhanced.pkl"
    else:
        project_path = "./RAG_project.py"
        kb_path = "knowledge_base.pkl"

    if not os.path.exists(project_path):
        print(f"Error: {project_path} not found.")
        return

    RAGLogSystem = import_rag_system(project_path)
    rag = RAGLogSystem()
    
    # --- APPLY PATCH ---
    print("[INFO] Patching RAG system to use Local LLM...")
    rag._call_gemini_api = types.MethodType(_call_local_llm_api_patch, rag)
    # -------------------
    
    # Configure Model (Logic reused but the actual call is patched)
    # We set internal vars just in case, though patch overrides usage
    rag.set_gemini_config(model_name="gemma3:4b", rpm_limit=9, use_sdk=False)
    
    # 1. Load Data
    print("Loading data...")
    sysmon_path = r"./sysmon"
    
    if not os.path.exists(sysmon_path):
        print(f"Warning: {sysmon_path} does not exist.")
    
    train_df, test_df = rag.load_and_split_data(sysmon_path)
    if train_df is None:
        print("Failed to load data. Exiting.")
        return

    # 3. Build or Load Knowledge Base
    if os.path.exists(kb_path):
        print(f"Loading Knowledge Base from {kb_path}...")
        if not rag.load_knowledge_base(kb_path):
            print("Failed to load KB, rebuilding...")
            rag.build_knowledge_base(train_df)
            rag.save_knowledge_base(kb_path)
    else:
        rag.build_knowledge_base(train_df)
        rag.save_knowledge_base(kb_path)
    
    # 4. Limit Test Set with Stratified Sampling
    SAMPLE_SIZE = args.sample_size
    RANDOM_SEED = 55
    print(f"\n[INFO] Limiting test set to random {SAMPLE_SIZE} logs.")
    
    label_col = 'label' if args.sequence else 'Label'
    
    if label_col in test_df.columns:
        normal_logs = test_df[test_df[label_col].astype(str).str.lower() == 'normal']
        mal_logs = test_df[test_df[label_col].astype(str).str.lower() == 'malicious']
    else:
        print(f"Warning: '{label_col}' column not found. Using available columns: {test_df.columns}")
        if 'Label' in test_df.columns: normal_logs = test_df[test_df['Label'] == 'Normal']; mal_logs = test_df[test_df['Label'] == 'Malicious']
        elif 'label' in test_df.columns: normal_logs = test_df[test_df['label'] == 'Normal']; mal_logs = test_df[test_df['label'] == 'Malicious']
        else: normal_logs, mal_logs = pd.DataFrame(), pd.DataFrame() 

    n_bs = min(len(normal_logs), SAMPLE_SIZE // 2)
    n_mal = min(len(mal_logs), SAMPLE_SIZE // 2)
    
    subset_normal = normal_logs.sample(n=n_bs, random_state=RANDOM_SEED) if not normal_logs.empty else pd.DataFrame()
    subset_mal = mal_logs.sample(n=n_mal, random_state=RANDOM_SEED) if not mal_logs.empty else pd.DataFrame()
    
    test_subset = pd.concat([subset_normal, subset_mal]).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    
    print(f"[INFO] Stratified Sample: {len(subset_normal)} Normal, {len(subset_mal)} Malicious.")
    
    # 5. Run Evaluation
    if args.sequence:
        results = await rag.evaluate_batch(test_subset, dry_run=args.dry_run)
    else:
        results = await rag.evaluate_batch(test_subset, mode='mixed', metric='cosine', dry_run=args.dry_run)
    
    print("\nSmall Sample Evaluation Complete.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
