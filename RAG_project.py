import numpy as np
import httpx
import asyncio
import json
import pandas as pd
from pathlib import Path
from sentence_transformers import SentenceTransformer
from scipy.spatial.distance import cosine, euclidean, cityblock
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import torch
import os
import pickle
import pickle
import time
try:
    from google import genai
    HAS_GENAI_SDK = True
except ImportError:
    HAS_GENAI_SDK = False
from pathlib import Path

# --- Configuration & Constants ---
MODEL_NAME = 'all-MiniLM-L6-v2'
API_KEY = os.getenv("GEMINI_API_KEY", "")  # User to provide API Key or set env var 'GEMINI_API_KEY'
# Default values
DEFAULT_LLM_MODEL = "gemini-2.5-flash-lite"
DEFAULT_RPM = 60

MAX_RETRIES = 5

class RAGLogSystem:
    def __init__(self, api_key=API_KEY, model_name=MODEL_NAME):
        """
        Initialize the RAGLog System.
        """
        self.api_key = api_key
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        print(f"Loading SentenceTransformer model '{model_name}' on {self.device}...")
        try:
            self.embedder = SentenceTransformer(model_name, device=self.device)
        except Exception as e:
            print(f"Error loading model: {e}")
            raise

        # Knowledge Base Storage
        self.kb_vectors = None
        self.kb_templates = [] # List of strings
        self.kb_labels = []    # List of 'Normal' or 'Malicious'

        # HTTP Client for Gemini
        self.client = httpx.AsyncClient()
        
        # LLM Configuration
        self.llm_model_name = DEFAULT_LLM_MODEL
        self.rpm_limit = DEFAULT_RPM
        self.use_sdk = False
        self.sdk_client = None

    def set_gemini_config(self, model_name=None, rpm_limit=None, use_sdk=False):
        """
        Configure the Gemini Model and Rate Limit.
        
        Args:
            model_name (str): e.g., 'gemini-1.5-flash', 'gemma-2-27b-it'.
            rpm_limit (int): Requests per minute limit.
            use_sdk (bool): If True, use google.genai SDK instead of REST API.
        """
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

    # --- Data Loading & Preparation ---

    # --- Data Loading & Preparation ---

    def parse_sysmon_xml(self, xml_path):
        """
        Parse Sysmon XML to extract specific fields for the template.
        Returns a list of dictionary items (template, label).
        """
        import xml.etree.ElementTree as ET
        
        events = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            # Handle Namespace
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

            for event in root.findall('ns:Event', ns):
                try:
                    sys_node = event.find('ns:System', ns)
                    event_id = sys_node.find('ns:EventID', ns).text
                    
                    data_node = event.find('ns:EventData', ns)
                    data_items = {d.get('Name'): d.text for d in data_node.findall('ns:Data', ns)}
                    
                    # We focus on EventID 1 (Process Creation) for this specific template format
                    # But capture others generically if needed.
                    # Handle various Sysmon Event IDs
                    if event_id == '1': # Process Create
                        parent_img = data_items.get('ParentImage', 'Unknown').split('\\')[-1]
                        img = data_items.get('Image', 'Unknown').split('\\')[-1]
                        cmd_line = data_items.get('CommandLine', '')
                        template = f"Sysmon EventID 1: Parent process {parent_img} spawned {img} with command line arguments {cmd_line}."
                    
                    elif event_id == '3': # Network Connection
                        img = data_items.get('Image', 'Unknown').split('\\')[-1]
                        dest_ip = data_items.get('DestinationIp', 'Unknown')
                        dest_port = data_items.get('DestinationPort', 'Unknown')
                        proto = data_items.get('Protocol', 'Unknown')
                        template = f"Sysmon EventID 3: Process {img} initiated {proto} connection to {dest_ip}:{dest_port}."
                        
                    elif event_id == '5': # Process Terminate
                        img = data_items.get('Image', 'Unknown').split('\\')[-1]
                        template = f"Sysmon EventID 5: Process {img} terminated."

                    elif event_id == '11': # File Create
                        img = data_items.get('Image', 'Unknown').split('\\')[-1]
                        target_file = data_items.get('TargetFilename', 'Unknown')
                        template = f"Sysmon EventID 11: Process {img} created file {target_file}."

                    elif event_id in ['12', '13', '14']: # Registry Events
                        img = data_items.get('Image', 'Unknown').split('\\')[-1]
                        target_obj = data_items.get('TargetObject', 'Unknown')
                        count = len(data_items) # Just to distinguish slightly? No, stick to key info.
                        event_type = data_items.get('EventType', 'RegistryEvent')
                        template = f"Sysmon EventID {event_id}: Process {img} performed {event_type} on {target_obj}."

                    elif event_id == '22': # DNS Query
                        img = data_items.get('Image', 'Unknown').split('\\')[-1]
                        query = data_items.get('QueryName', 'Unknown')
                        template = f"Sysmon EventID 22: Process {img} queried DNS for {query}."
                    
                    else: # Generic Fallback
                        # Construct a generic string with available keys (limit to first 3-4 to avoid massive prompts)
                        details = ", ".join([f"{k}={v}" for k, v in list(data_items.items())[:4]])
                        template = f"Sysmon EventID {event_id}: {details}..."
                    
                    events.append(template)
                except Exception as e:
                    continue # Skip malformed events
                    
        except Exception as e:
            print(f"Failed to parse {xml_path}: {e}")
            
        return events

    def load_data_from_directory(self, root_dir):
        """
        Load XML logs from 'benign' and 'mal' subdirectories.
        """
        records = []
        root_path = Path(root_dir)
        
        # Define categories mapping
        categories = {'benign': 'Normal', 'mal': 'Malicious'}
        
        for subdir, label in categories.items():
            dir_path = root_path / subdir
            if not dir_path.exists():
                print(f"Warning: Directory {dir_path} not found.")
                continue
                
            print(f"Loading {label} logs from {dir_path}...")
            files = list(dir_path.glob('*.xml'))
            for f in files:
                templates = self.parse_sysmon_xml(f)
                for t in templates:
                    records.append({'EventTemplate': t, 'Label': label})
                    
        if not records:
            print("No records found.")
            return None
            
        return pd.DataFrame(records)

    def load_and_split_data(self, source_path):
        """
        Load data from CSV or Directory (XML) and split.
        """
        df = None
        if os.path.isdir(source_path):
            df = self.load_data_from_directory(source_path)
        else:
            # Fallback to CSV loading
            try:
                df = pd.read_csv(source_path)
            except:
                pass

        if df is None or df.empty:
            print("Error: No data loaded.")
            return None, None
            
        print(f"Total Logs Loaded: {len(df)}")
        # Split 80/20
        train_df, test_df = train_test_split(df, test_size=0.2, shuffle=True, random_state=42)
        print(f"Train: {len(train_df)}, Test: {len(test_df)}")
        
        return train_df, test_df

    def build_knowledge_base(self, train_df):
        """
        Build the Knowledge Base from the Training set.
        Indexes ALL logs (Normal & Malicious) to support Mixed retrieval mode.
        """
        print("Building Knowledge Base...")
        
        # Deduplicate to avoid retrieving identical logs
        # We keep the first occurrence of each unique template
        unique_df = train_df.drop_duplicates(subset=['EventTemplate']).copy()
        print(f"Duplicates removed. Unique templates: {len(unique_df)} (Original: {len(train_df)})")
        
        templates = unique_df['EventTemplate'].tolist()
        labels = unique_df['Label'].tolist()
        
        # Batch Encode
        embeddings = self.embedder.encode(templates, convert_to_numpy=True, show_progress_bar=True)
        
        self.kb_vectors = embeddings
        self.kb_templates = unique_df['EventTemplate'].reset_index(drop=True)
        self.kb_labels = unique_df['Label'].reset_index(drop=True)
        
        print(f"Knowledge Base Index Size: {self.kb_vectors.shape[0]}")

    def save_knowledge_base(self, path):
        """Save the Knowledge Base to a pickle file."""
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
        """Load the Knowledge Base from a pickle file."""
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

    # --- Retrieval Module ---

    def retrieve(self, query_log, mode='normal', metric='cosine', k=5):
        """
        Retrieve Top-K similar logs based on mode and metric.
        
        Args:
            query_log (str): The log entry to check.
            mode (str): 'normal' (retrieve only normal logs) or 'mixed' (retrieve both).
            metric (str): 'cosine', 'euclidean', 'manhattan'.
            k (int): Number of neighbors to retrieve.
        """
        # 1. Embed Query
        query_vector = self.embedder.encode([query_log], convert_to_numpy=True)[0]
        
        # 2. Filter KB based on Mode
        if mode.lower() == 'normal':
            indices = [i for i, label in enumerate(self.kb_labels) if label.lower() == 'normal']
        else: # 'mixed'
            indices = list(range(len(self.kb_labels)))
            
        if not indices:
            return []

        filtered_vectors = self.kb_vectors[indices]
        filtered_templates = self.kb_templates.iloc[indices].tolist()
        filtered_labels = self.kb_labels.iloc[indices].tolist()

        # 3. Calculate Distance
        distances = []
        for vec in filtered_vectors:
            if metric == 'cosine':
                d = cosine(query_vector, vec)
            elif metric == 'euclidean':
                d = euclidean(query_vector, vec)
            elif metric == 'manhattan':
                d = cityblock(query_vector, vec)
            else:
                d = cosine(query_vector, vec) # Default
            distances.append(d)
        
        distances = np.array(distances)
        
        # 4. Get Top-K
        # For distances, smaller is better.
        top_k_idx = np.argsort(distances)[:k]
        
        results = []
        for idx in top_k_idx:
            # Convert distance to similarity for display (Cosine only standardizes well to 0-1, others vary)
            sim_score = 1 - distances[idx] if metric == 'cosine' else -distances[idx]
            
            results.append({
                "template": filtered_templates[idx],
                "label": filtered_labels[idx],
                "metric_score": distances[idx],
                "similarity_display": sim_score
            })
            
        return results

    # --- Generation & Decision Module ---

    async def _call_gemini_api(self, payload):
        """Exponential backoff API call (REST or SDK)."""
        
        # --- SDK PATH ---
        if self.use_sdk and self.sdk_client:
            # Payload adaptation for SDK might be needed if structure differs
            # For simplicity, assuming payload 'contents' matches SDK 'contents'
            # But specific SDK call might be simpler: model.generate_content(contents=...)
            prompt_text = payload['contents'][0]['parts'][0]['text']
            system_inst = payload.get('systemInstruction', {}).get('parts', [{}])[0].get('text', '')
            
            # The SDK might run synchronously? wrap in thread if needed, or check if it supports async
            # Official SDK usually sync. We can run in executor if needed for true async.
            # strict async needed? For now, just run it.
            
            try:
                # Assuming SDK usage: client.models.generate_content(...)
                # Config: response_mime_type="application/json"
                config = {"response_mime_type": "application/json"} if "application/json" in str(payload) else None
                
                # Adapting to user provided snippet style
                # response = client.models.generate_content(model=..., contents=..., config=...)
                
                # Note: This is a synchronous call. Since we are in async method, 
                # blocking here stops the event loop. ideally run_in_executor.
                # But for this user request, direct call is fine as proof of concept.
                response = self.sdk_client.models.generate_content(
                    model=self.llm_model_name,
                    contents=prompt_text,
                    config=genai.types.GenerateContentConfig(
                        system_instruction=system_inst,
                        response_mime_type="application/json"
                    )
                )
                
                # Retrieve text
                # SDK response object has .text or .candidates...
                # We need to return a dict structure similar to REST for downstream parsing
                # Mocking REST structure:
                return {
                    'candidates': [
                        {'content': {'parts': [{'text': response.text}]}}
                    ]
                }
            except Exception as e:
                print(f"SDK Error: {e}")
                return None

        # --- REST API PATH ---
        headers = {'Content-Type': 'application/json'}
        # Construct dynamic URL
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.llm_model_name}:generateContent"
        
        for attempt in range(MAX_RETRIES):
            try:
                response = await self.client.post(f"{url}?key={self.api_key}", headers=headers, json=payload, timeout=30)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code in [429, 500, 503] and attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    print(f"API Error: {e}")
                    return None
            except Exception as e:
                print(f"Network Error: {e}")
                return None
        return None

    def _create_prompt(self, query_log, retrieved_context):
        """Construct prompt with explicit Context Labeling."""
        context_str = "\n".join([
            f"- [{item['label'].upper()}] {item['template']} (Dist: {item['metric_score']:.4f})" 
            for item in retrieved_context
        ])

        system_prompt = (
            "You are a cybersecurity expert specializing in Sysmon log analysis. "
            "Your task is to detect if the 'Target Log' is ANOMALOUS based on the provided 'Reference Context'.\n"
            "The Reference Context contains historical logs labeled as [NORMAL] or [MALICIOUS/ANOMALY].\n"
            "1. If the Target Log semantically matches a [NORMAL] reference, it is likely NORMAL.\n"
            "2. If it matches a [MALICIOUS] reference, or deviates significantly from all [NORMAL] references, it is ANOMALOUS.\n"
            "Output valid JSON."
        )

        user_query = (
            f"Reference Context (Knowledge Base):\n{context_str}\n\n"
            f"Target Log:\n'{query_log}'\n\n"
            "Determine if the Target Log is an ANOMALY.\n"
            "Output Format:\n"
            "{\n"
            "  \"classification\": \"Normal\" OR \"Malicious\",\n"
            "  \"reasoning\": \"Explain why, citing specific reference logs.\"\n"
            "}"
        )
        return system_prompt, user_query

    async def detect_anomaly(self, query_log, mode='normal', metric='cosine', dry_run=False):
        """Full Pipeline: Retrieve -> Prompt -> Decide"""
        retrieved = self.retrieve(query_log, mode=mode, metric=metric)
        
        system_prompt, user_query = self._create_prompt(query_log, retrieved)
        
        # --- DEBUG LOGGING TO FILE ---
        try:
            with open("prompt_log.txt", "a", encoding="utf-8") as f:
                f.write("\n" + "="*50 + "\n")
                if dry_run:
                    f.write(" [DRY RUN] Prompt Not Sent to LLM\n")
                f.write(f" [DEBUG] Target Log: {query_log}\n")
                f.write("-" * 20 + "\n")
                f.write(" [DEBUG] Retrieved Context:\n")
                for r in retrieved:
                    f.write(f"   - [{r['label']}] {r['template']} (Sim: {r['similarity_display']:.4f})\n")
                f.write("-" * 20 + "\n")
                f.write(" [DEBUG] Combined Prompt (User Query Part):\n")
                f.write(user_query + "\n")
                f.write("="*50 + "\n\n")
        except Exception as e:
            print(f"Error writing to log file: {e}")
        # -------------------

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
                print(f"Parsing Error: {e}")
                return {"classification": "Error", "reasoning": str(e)}
        return {"classification": "Error", "reasoning": "No response"}

    # --- Evaluation ---

    async def evaluate_batch(self, test_df, mode='mixed', metric='cosine', dry_run=False):
        """Batch evaluation pipeline."""
        y_true = []
        y_pred = []
        
        print(f"\n--- Starting Batch Evaluation (N={len(test_df)}, DryRun={dry_run}) ---")
        
        for index, row in test_df.iterrows():
            log = row['EventTemplate']
            label = row['Label'] # Assuming 'Normal' or 'Anomaly'
            
            # Run Detection
            result = await self.detect_anomaly(log, mode=mode, metric=metric, dry_run=dry_run)
            pred = result.get('classification', 'Error')
            
            # Normalize labels for metrics
            y_true.append(1 if label.lower() in ['anomaly', 'malicious'] else 0)
            y_pred.append(1 if pred.lower() in ['anomaly', 'anomalous', 'malicious'] else 0)
            
            print(f"[{index+1}/{len(test_df)}] True: {label} | Pred: {pred} | Reason: {result.get('reasoning', '')[:50]}...")
            
            # Rate Limiting (30 RPM ~ 2 seconds per request)
            # Adding small buffer -> 2.1 seconds
            # Rate Limiting
            if not dry_run and self.rpm_limit > 0:
                sleep_time = 60.0 / self.rpm_limit
                await asyncio.sleep(sleep_time) 
        
        if dry_run:
            print("\nDry Run Complete. No metrics calculated.")
            return None

        # Metrics
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

# --- Main Execution ---
if __name__ == "__main__":
    print("Please run 'evaluation.py' or 'evaluation_small_sample.py' to evaluate on the real dataset.")
