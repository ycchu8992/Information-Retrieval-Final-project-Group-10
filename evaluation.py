import asyncio
import argparse
import pandas as pd
from pathlib import Path
import importlib.util
import sys
import os


# Helper to import the RAG system dynamically
def import_rag_system(file_path):
    spec = importlib.util.spec_from_file_location("RAG_project", file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["RAG_project"] = module
    spec.loader.exec_module(module)
    spec.loader.exec_module(module)
    if hasattr(module, 'RAGLogSystem'):
        return module.RAGLogSystem
    return module.RAGSequenceSystem

async def main():
    parser = argparse.ArgumentParser(description="Eval Script")
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

    print(f"--- Small Sample Evaluation (N={args.sample_size}, DryRun={args.dry_run}) ---")
    
    # Clear previous prompt log
    if os.path.exists("prompt_log.txt"):
        try:
            os.remove("prompt_log.txt")
            print("Cleared previous prompt_log.txt")
        except Exception as e:
            print(f"Warning: Could not clear prompt_log.txt: {e}")
    
    # Check for API Key
    if not os.getenv("GEMINI_API_KEY"):
        print("\n[WARNING] GEMINI_API_KEY environment variable is NOT set.")
        print("Please set it before running: export GEMINI_API_KEY='your_key_here'")
        print("Or ensure it is hardcoded in RAG_project.py (not recommended).")
        # specific to windows
        if os.name == 'nt':
             print("Windows PowerShell: $env:GEMINI_API_KEY='your_key_here'")
             print("Windows CMD: set GEMINI_API_KEY=your_key_here\n")

    # 1. Initialize System
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
    
    # Configure Model and Rate Limit (Example with SDK)
    rag.set_gemini_config(model_name="gemini-2.5-flash-lite", rpm_limit=9, use_sdk=True)
    
    # 1. Load Data
    # 1. Load Data
    print("Loading data...")
    # Using the absolute path to the sysmon directory
    sysmon_path = r"./sysmon"
    print(f"Checking path: {sysmon_path}")
    print(f"Exists: {os.path.exists(sysmon_path)}")
    print(f"Is Dir: {os.path.isdir(sysmon_path)}")
    train_df, test_df = rag.load_and_split_data(sysmon_path)
    if train_df is None:
        print("Failed to load data. Exiting.")
        return

    # 3. Build or Load Knowledge Base
    if os.path.exists(kb_path):
        print(f"Loading Knowledge Base from {kb_path}...")
        # Use a consistent naming for the KB file based on version
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
    print(f"\n[INFO] Limiting test set to random {SAMPLE_SIZE} logs (Stratified: ~{SAMPLE_SIZE//2} Normal, ~{SAMPLE_SIZE//2} Malicious).")
    
    # Stratified Sampling
    # Stratified Sampling
    # Sequence mode uses 'label', others use 'Label' - standardize this?
    # RAG_project_sequence.py uses lowercase 'label'
    label_col = 'label' if args.sequence else 'Label'
    
    if label_col in test_df.columns:
        # Normalize to title case for matching if needed, or check values
        # Sequence DF has "Normal"/"Malicious". Enhanced has "Normal"/"Malicious".
        # Let's ensure access is safe
        normal_logs = test_df[test_df[label_col].astype(str).str.lower() == 'normal']
        mal_logs = test_df[test_df[label_col].astype(str).str.lower() == 'malicious']
    else:
        # Fallback if column names differ unexpectedly
        print(f"Warning: '{label_col}' column not found. Using available columns: {test_df.columns}")
        # Try to guess
        if 'Label' in test_df.columns: normal_logs = test_df[test_df['Label'] == 'Normal']; mal_logs = test_df[test_df['Label'] == 'Malicious']
        elif 'label' in test_df.columns: normal_logs = test_df[test_df['label'] == 'Normal']; mal_logs = test_df[test_df['label'] == 'Malicious']
        else: normal_logs, mal_logs = pd.DataFrame(), pd.DataFrame() # fail gracefully

    # Take up to 25 from each, or whatever is available
    n_bs = min(len(normal_logs), SAMPLE_SIZE // 2)
    n_mal = min(len(mal_logs), SAMPLE_SIZE // 2)
    
    # Stratified or Random if stats are poor
    subset_normal = normal_logs.sample(n=n_bs, random_state=RANDOM_SEED) if not normal_logs.empty else pd.DataFrame()
    subset_mal = mal_logs.sample(n=n_mal, random_state=RANDOM_SEED) if not mal_logs.empty else pd.DataFrame()
    
    test_subset = pd.concat([subset_normal, subset_mal]).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    
    print(f"[INFO] Stratified Sample: {len(subset_normal)} Normal, {len(subset_mal)} Malicious.")
    
    # 5. Run Evaluation
    # 5. Run Evaluation
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
