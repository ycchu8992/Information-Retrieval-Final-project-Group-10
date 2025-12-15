import asyncio
import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import httpx
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
import re
import torch
import os
import pickle
import time
try:
    from google import genai
    HAS_GENAI_SDK = True
except ImportError:
    HAS_GENAI_SDK = False

# --- Configuration & Constants ---
MODEL_NAME = 'all-MiniLM-L6-v2' # Keeping default as per strict user instruction for this file
API_KEY = os.getenv("GEMINI_API_KEY", "") 

DEFAULT_LLM_MODEL = "gemini-2.5-flash-lite"
DEFAULT_RPM = 60
MAX_RETRIES = 5

class RAGLogSystem:
    def __init__(self):
        # Initialize Encoder
        print(f"Loading SentenceTransformer model '{MODEL_NAME}' on cuda..." if torch.cuda.is_available() else " on cpu...")
        self.encoder = SentenceTransformer(MODEL_NAME, device='cuda' if torch.cuda.is_available() else 'cpu')
        self.api_key = API_KEY
        
        # Knowledge Base Memory
        self.kb_vectors = None
        self.kb_templates = None
        self.kb_labels = None
        
        # HTTP Client
        self.client = httpx.AsyncClient()
        
        # LLM Config
        self.llm_model_name = DEFAULT_LLM_MODEL
        self.rpm_limit = DEFAULT_RPM
        self.use_sdk = False
        self.sdk_client = None

    def set_gemini_config(self, model_name=None, rpm_limit=None, use_sdk=False):
        if model_name:
            self.llm_model_name = model_name
            print(f"LLM Model set to: {self.llm_model_name}")
        if rpm_limit is not None:
            self.rpm_limit = rpm_limit
            print(f"RPM Limit set to: {self.rpm_limit}")
        
        if use_sdk:
            if HAS_GENAI_SDK:
                self.use_sdk = True
                if not self.sdk_client:
                    self.sdk_client = genai.Client(api_key=self.api_key)
                print("Switched to Google GenAI SDK.")
            else:
                print("Warning: 'google-genai' package not installed. Falling back to REST API.")
                self.use_sdk = False

    # --- ENHANCEMENT: CANONICALIZATION ---
    def canonicalize_text(self, text):
        """
        Clean text to remove noise (GUIDs, User Paths, Temp files).
        """
        if not text: return ""
        
        # 1. User Directories: C:\Users\JohnDoe\ -> <USER_PATH>\
        text = re.sub(r'C:\\Users\\[^\\]+\\', r'<USER_PATH>\\', text, flags=re.IGNORECASE)
        
        # 2. GUIDs: 8-4-4-4-12 hex digits
        # e.g., {7A076CE1-4B31-412C-9C5B-000000000000} or just 7A076CE1-4B31...
        text = re.sub(r'\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?', r'<GUID>', text)
        
        # 3. Temp Files: ~DF1234.tmp or .tmp extension generally?
        # User example: ~DF123.tmp -> <TMP_FILE>
        text = re.sub(r'~[a-zA-Z0-9]+\.tmp', r'<TMP_FILE>', text, flags=re.IGNORECASE)
        
        # 4. Hex Strings (long pointers): 0x00007FF...
        text = re.sub(r'0x[0-9a-fA-F]{8,}', r'<HEX_PTR>', text)

        return text

    # --- ENHANCED PARSING ---
    def parse_sysmon_xml(self, xml_path):
        """
        Parse Sysmon XML -> Canonicalize -> Structure.
        Returns unique structured strings.
        structure: Process: [Image] | Command: [CommandLine] | ...
        """
        events = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

            for event in root.findall('ns:Event', ns):
                try:
                    sys_node = event.find('ns:System', ns)
                    event_id = sys_node.find('ns:EventID', ns).text
                    
                    data_node = event.find('ns:EventData', ns)
                    data_items = {d.get('Name'): d.text for d in data_node.findall('ns:Data', ns)}
                    
                    # Apply Canonicalization to VALUES
                    clean_items = {k: self.canonicalize_text(v) for k, v in data_items.items()}
                    
                    template = ""
                    
                    # STRUCTURED FORMATTING
                    if event_id == '1': # Process Create
                        # Structure: Process: [Image] | Command: [CommandLine] | Parent: [ParentImage]
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        parent = clean_items.get('ParentImage', 'Unknown').split('\\')[-1]
                        cmd = clean_items.get('CommandLine', '')
                        template = f"Sysmon EventID 1: Process: {img} | Command: {cmd} | Parent: {parent}"
                    
                    elif event_id == '3': # Network
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        dst = f"{clean_items.get('DestinationIp')}:{clean_items.get('DestinationPort')}"
                        proto = clean_items.get('Protocol')
                        template = f"Sysmon EventID 3: Process: {img} | Proto: {proto} | Dest: {dst}"
                        
                    elif event_id == '5': # Terminate
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        template = f"Sysmon EventID 5: Process: {img} | Action: Terminated"

                    elif event_id == '11': # File Create
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        target = clean_items.get('TargetFilename', 'Unknown')
                        template = f"Sysmon EventID 11: Process: {img} | Created: {target}"

                    elif event_id in ['12', '13', '14']:
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        target = clean_items.get('TargetObject', 'Unknown')
                        evt = clean_items.get('EventType', 'RegistryEvent')
                        template = f"Sysmon EventID {event_id}: Process: {img} | Event: {evt} | Target: {target}"

                    elif event_id == '22':
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        query = clean_items.get('QueryName', 'Unknown')
                        template = f"Sysmon EventID 22: Process: {img} | DNS Query: {query}"
                    
                    else:
                        details = " | ".join([f"{k}: {v}" for k, v in list(clean_items.items())[:4]])
                        template = f"Sysmon EventID {event_id}: {details}"
                    
                    events.append(template)
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"Failed to parse {xml_path}: {e}")
            
        return events

    # --- Data Loading (Same as before) ---
    def load_data_from_directory(self, root_dir):
        data = []
        benign_path = os.path.join(root_dir, 'benign')
        print(f"Loading Normal logs from {benign_path}...")
        if os.path.exists(benign_path):
            files = [f for f in os.listdir(benign_path) if f.endswith(".xml")]
            for file in files:
                templates = self.parse_sysmon_xml(os.path.join(benign_path, file))
                for t in templates:
                    data.append({'EventTemplate': t, 'Label': 'Normal'})

        mal_path = os.path.join(root_dir, 'mal')
        print(f"Loading Malicious logs from {mal_path}...")
        if os.path.exists(mal_path):
            files = [f for f in os.listdir(mal_path) if f.endswith(".xml")]
            for file in files:
                templates = self.parse_sysmon_xml(os.path.join(mal_path, file))
                for t in templates:
                    data.append({'EventTemplate': t, 'Label': 'Malicious'})
        
        return pd.DataFrame(data)

    def load_and_split_data(self, source_path):
        df = None
        if os.path.isdir(source_path):
            df = self.load_data_from_directory(source_path)
        else:
            try:
                df = pd.read_csv(source_path)
            except:
                pass

        if df is None or df.empty:
            print("Error: No data loaded.")
            return None, None
            
        print(f"Total Logs Loaded: {len(df)}")
        train_df, test_df = train_test_split(df, test_size=0.2, shuffle=True, random_state=42)
        print(f"Train: {len(train_df)}, Test: {len(test_df)}")
        return train_df, test_df

    # --- Knowledge Base (Same logic, new content) ---
    def build_knowledge_base(self, train_df):
        print("Building Knowledge Base...")
        unique_entries = train_df.drop_duplicates(subset=['EventTemplate'])
        print(f"Duplicates removed. Unique templates: {len(unique_entries)} (Original: {len(train_df)})")
        
        self.kb_templates = unique_entries['EventTemplate'].tolist()
        self.kb_labels = unique_entries['Label'].tolist()
        
        print("Embedding Knowledge Base...")
        self.kb_vectors = self.encoder.encode(self.kb_templates, convert_to_numpy=True, show_progress_bar=True)
        print(f"Knowledge Base Index Size: {len(self.kb_vectors)}")

    def save_knowledge_base(self, path):
        try:
            with open(path, 'wb') as f:
                data = {
                    'vectors': self.kb_vectors,
                    'templates': self.kb_templates,
                    'labels': self.kb_labels
                }
                pickle.dump(data, f)
            print(f"Knowledge Base saved to {path}")
        except Exception as e:
            print(f"Error saving Knowledge Base: {e}")

    def load_knowledge_base(self, path):
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)
                self.kb_vectors = data['vectors']
                self.kb_templates = data['templates']
                self.kb_labels = data['labels']
            print(f"Knowledge Base loaded from {path}")
            return True
        except Exception as e:
            print(f"Error loading Knowledge Base: {e}")
            return False

    # --- Retrieval & Detection ---
    def retrieve(self, query_log, k=5, mode='mixed', metric='cosine'):
        # Just ensure query is also canonicalized/structured if passed raw?
        # Assuming query_log comes from the dataframe which is already processed.
        # But if it comes from raw input, we might need to process it.
        # For this pipeline, evaluation passes df content, so it's fine.
        
        query_vec = self.encoder.encode([query_log], convert_to_numpy=True)
        
        if metric == 'cosine':
            sims = cosine_similarity(query_vec, self.kb_vectors)[0]
        else: # Euclidean
            dists = np.linalg.norm(self.kb_vectors - query_vec, axis=1)
            sims = 1 / (1 + dists)
            
        indices = np.argsort(sims)[::-1][:k]
        
        retrieved = []
        for idx in indices:
            retrieved.append({
                'template': self.kb_templates[idx],
                'label': self.kb_labels[idx],
                'similarity': float(sims[idx]),
                'similarity_display': float(sims[idx]) # consistency
            })
        return retrieved

    def _create_prompt(self, target_log, retrieved_context):
        context_str = "\n".join([
            f"- [{r['label']}] {r['template']} (Sim: {r['similarity_display']:.4f})" 
            for r in retrieved_context
        ])
        
        system_instruction = (
            "You are an expert Cyber Security Analyst.\n"
            "Your task is to detect malicious Sysmon logs based on the provided Knowledge Base context.\n"
            "You will receive a TARGET LOG and a list of RETRIEVED SIMILAR LOGS from the database.\n"
            "Analyze the Target Log's 'Process', 'Command', and 'Parent' carefully.\n"
            "If the Target Log identical to or highly similar to a Known-Normal log, classify it as 'Normal'.\n"
            "If the Target Log aligns with Known-Malicious patterns (e.g., suspicious PowerShell, non-standard paths), classify as 'Malicious'.\n"
            "Ignore noise like random GUIDs (<GUID>) or temp paths (<TMP_FILE>) unless they are part of a known attack pattern."
        )
        
        user_query = (
            f"Reference Context (Knowledge Base):\n{context_str}\n\n"
            f"Target Log:\n{target_log}\n\n"
            "Determine if the Target Log is an ANOMALY.\n"
            "Output Format:\n"
            "{\n"
            "  \"classification\": \"Normal\" OR \"Malicious\",\n"
            "  \"reasoning\": \"Explain why, citing specific reference logs.\"\n"
            "}"
        )
        return system_instruction, user_query

    async def _call_gemini_api(self, payload):
        """Exponential backoff API call (REST or SDK)."""
        if self.use_sdk and self.sdk_client:
            prompt_text = payload['contents'][0]['parts'][0]['text']
            system_inst = payload.get('systemInstruction', {}).get('parts', [{}])[0].get('text', '')
            try:
                response = self.sdk_client.models.generate_content(
                    model=self.llm_model_name,
                    contents=prompt_text,
                    config=genai.types.GenerateContentConfig(
                        system_instruction=system_inst,
                        response_mime_type="application/json"
                    )
                )
                return {'candidates': [{'content': {'parts': [{'text': response.text}]}}]}
            except Exception as e:
                print(f"SDK Error: {e}")
                return None

        headers = {'Content-Type': 'application/json'}
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.llm_model_name}:generateContent"
        
        for attempt in range(MAX_RETRIES):
            try:
                response = await self.client.post(f"{url}?key={self.api_key}", headers=headers, json=payload, timeout=30)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    wait = 2 ** attempt
                    print(f"429 Too Many Requests. Retrying in {wait}s...")
                    await asyncio.sleep(wait)
                else:
                    print(f"API Error: {e}")
                    return None
            except Exception as e:
                print(f"Request failed: {e}")
                return None
        return None

    async def detect_anomaly(self, query_log, mode='normal', metric='cosine', dry_run=False):
        retrieved = self.retrieve(query_log, mode=mode, metric=metric)
        system_prompt, user_query = self._create_prompt(query_log, retrieved)
        
        # Log Prompt
        try:
            with open("prompt_log_enhanced.txt", "a", encoding="utf-8") as f:
                f.write("\n" + "="*50 + "\n")
                if dry_run: f.write(" [DRY RUN] Prompt Not Sent to LLM\n")
                f.write(f" [DEBUG] Target Log: {query_log}\n")
                f.write("-" * 20 + "\n")
                f.write(" [DEBUG] Retrieved Context:\n")
                for r in retrieved:
                    f.write(f"   - [{r['label']}] {r['template']} (Sim: {r['similarity_display']:.4f})\n")
                f.write("="*50 + "\n\n")
        except: pass

        if dry_run:
            return {"classification": "DryRun", "reasoning": "Prompt created and logged. No API call made."}
                
        payload = {
            "contents": [{"parts": [{"text": user_query}]}],
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "generationConfig": {"responseMimeType": "application/json"}
        }

        response = await self._call_gemini_api(payload)
        
        if response and 'candidates' in response:
            try:
                text = response['candidates'][0]['content']['parts'][0]['text']
                decision = json.loads(text)
                return decision
            except Exception as e:
                return {"classification": "Error", "reasoning": str(e)}
        return {"classification": "Error", "reasoning": "No response"}

    async def evaluate_batch(self, test_df, mode='mixed', metric='cosine', dry_run=False):
        y_true = []
        y_pred = []
        print(f"\n--- Starting Enhanced Batch Evaluation (N={len(test_df)}, DryRun={dry_run}) ---")
        for index, row in test_df.iterrows():
            log = row['EventTemplate']
            label = row['Label']
            result = await self.detect_anomaly(log, mode=mode, metric=metric, dry_run=dry_run)
            pred = result.get('classification', 'Error')
            
            y_true.append(1 if label.lower() in ['anomaly', 'malicious'] else 0)
            y_pred.append(1 if pred.lower() in ['anomaly', 'anomalous', 'malicious'] else 0)
            
            print(f"[{index+1}/{len(test_df)}] True: {label} | Pred: {pred} | Reason: {result.get('reasoning', '')[:50]}...")
            
            if not dry_run and self.rpm_limit > 0:
                await asyncio.sleep(60.0 / self.rpm_limit) 
        
        if dry_run:
            print("\nDry Run Complete.")
            return None

        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred)
        
        print("\n--- Evaluation Results ---")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1 Score:  {f1:.4f}")
        print(f"Confusion Matrix (TN, FP, FN, TP):\n{cm}")
        return {"precision": precision, "recall": recall, "f1": f1, "cm": cm}
