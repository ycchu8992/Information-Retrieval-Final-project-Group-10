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
from datetime import datetime

try:
    from google import genai
    HAS_GENAI_SDK = True
except ImportError:
    HAS_GENAI_SDK = False

# --- Configuration & Constants ---
MODEL_NAME = 'all-MiniLM-L6-v2' 
API_KEY = os.getenv("GEMINI_API_KEY", "") 

DEFAULT_LLM_MODEL = "gemini-2.5-flash-lite"
DEFAULT_RPM = 60
MAX_RETRIES = 5
WINDOW_SIZE = 5

class RAGSequenceSystem:
    def __init__(self):
        # Initialize Encoder
        print(f"Loading SentenceTransformer model '{MODEL_NAME}' on cuda..." if torch.cuda.is_available() else " on cpu...")
        self.encoder = SentenceTransformer(MODEL_NAME, device='cuda' if torch.cuda.is_available() else 'cpu')
        self.api_key = API_KEY
        
        # Knowledge Base Memory
        self.kb_vectors = None
        self.kb_sequences = None # Stores the text of the sequence
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
                print("Switched to Google GenAI SDK (Sequence Mode).")
            else:
                print("Warning: 'google-genai' package not installed. Falling back to REST API.")
                self.use_sdk = False

    def canonicalize_text(self, text):
        """Clean text to remove noise (GUIDs, User Paths, Temp files)."""
        if not text: return ""
        text = re.sub(r'C:\\Users\\[^\\]+\\', r'<USER_PATH>\\', text, flags=re.IGNORECASE)
        text = re.sub(r'\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?', r'<GUID>', text)
        text = re.sub(r'~[a-zA-Z0-9]+\.tmp', r'<TMP_FILE>', text, flags=re.IGNORECASE)
        text = re.sub(r'0x[0-9a-fA-F]{8,}', r'<HEX_PTR>', text)
        return text

    def parse_sysmon_xml_with_time(self, xml_path):
        """
        Parse Sysmon XML -> Extract Time & Template.
        Returns list of dicts: {'time': datetime, 'template': str}
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
                    
                    # Extract Time
                    time_str = sys_node.find('ns:TimeCreated', ns).get('SystemTime')
                    # Handle Z and potentially variable microseconds
                    # 2022-07-19T20:00:55.542836000Z
                    # Truncate to microseconds (26 chars) if too long, or use simple str comparison since format is fixed width ISO usually
                    # But for safety lets convert to string that sorts correctly (ISO is fine)
                    
                    data_node = event.find('ns:EventData', ns)
                    data_items = {d.get('Name'): d.text for d in data_node.findall('ns:Data', ns)}
                    clean_items = {k: self.canonicalize_text(v) for k, v in data_items.items()}
                    
                    template = ""
                    if event_id == '1': # Process Create
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        parent = clean_items.get('ParentImage', 'Unknown').split('\\')[-1]
                        cmd = clean_items.get('CommandLine', '')
                        template = f"Sysmon ID 1: Process: {img} | Cmd: {cmd} | Parent: {parent}"
                    elif event_id == '3': # Network
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        dst = f"{clean_items.get('DestinationIp')}:{clean_items.get('DestinationPort')}"
                        proto = clean_items.get('Protocol')
                        template = f"Sysmon ID 3: Process: {img} | Proto: {proto} | Dest: {dst}"
                    elif event_id == '5': # Terminate
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        template = f"Sysmon ID 5: Process: {img} | Action: Terminated"
                    elif event_id == '11': # File Create
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        target = clean_items.get('TargetFilename', 'Unknown')
                        template = f"Sysmon ID 11: Process: {img} | Created: {target}"
                    elif event_id in ['12', '13', '14']:
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        target = clean_items.get('TargetObject', 'Unknown')
                        evt = clean_items.get('EventType', 'RegistryEvent')
                        template = f"Sysmon ID {event_id}: Process: {img} | Event: {evt} | Target: {target}"
                    elif event_id == '22':
                        img = clean_items.get('Image', 'Unknown').split('\\')[-1]
                        query = clean_items.get('QueryName', 'Unknown')
                        template = f"Sysmon ID 22: Process: {img} | DNS: {query}"
                    else:
                        details = " | ".join([f"{k}: {v}" for k, v in list(clean_items.items())[:4]])
                        template = f"Sysmon ID {event_id}: {details}"
                    
                    events.append({'time_str': time_str, 'template': template})
                except Exception as e:
                    continue
        except Exception as e:
            print(f"Failed to parse {xml_path}: {e}")
            
        return events

    def load_and_group_data(self, root_dir):
        """
        Load data, Sort by time, Create Sequences.
        """
        all_sequences = [] # list of {'sequence': str, 'label': str}
        
        # Helper to process a directory
        def process_directory(path, label):
            file_events = []
            if os.path.exists(path):
                files = [f for f in os.listdir(path) if f.endswith(".xml")]
                print(f"Processing {len(files)} files in {path}...")
                for file in files:
                    evs = self.parse_sysmon_xml_with_time(os.path.join(path, file))
                    file_events.extend(evs)
            
            # Sort all events by time for this class (Global sort assumption for now, or per file?)
            # Usually separating by file is cleaner if files represent different hosts/sessions.
            # But here we just dump them all? The implementation in standard RAG treated them independently.
            # Let's globally sort to simulated a continuous stream if they are related. 
            # If they are distinct hosts, sorting globally interweaves them which is BAD for sequencing.
            # Ideally: Group by File (Host) -> Sort -> Window -> Collect.
            # Let's assume File = Host/Session.
            
            sequences = []
            # We need to re-scan to do file-by-file windowing
            # Re-implementing correctly:
            if os.path.exists(path):
                files = [f for f in os.listdir(path) if f.endswith(".xml")]
                for file in files:
                    evs = self.parse_sysmon_xml_with_time(os.path.join(path, file))
                    # Sort events within the file
                    evs.sort(key=lambda x: x['time_str'])
                    
                    # Sliding Window
                    if len(evs) < WINDOW_SIZE:
                        continue # Skip short files
                        
                    for i in range(len(evs) - WINDOW_SIZE + 1):
                        window = evs[i : i + WINDOW_SIZE]
                        # Join templates with ' -> '
                        seq_str = " -> ".join([w['template'] for w in window])
                        sequences.append({'sequence': seq_str, 'label': label})
            return sequences

        benign_seqs = process_directory(os.path.join(root_dir, 'benign'), 'Normal')
        mal_seqs = process_directory(os.path.join(root_dir, 'mal'), 'Malicious')
        
        combined = benign_seqs + mal_seqs
        df = pd.DataFrame(combined)
        return df

    def load_and_split_data(self, source_path):
        df = self.load_and_group_data(source_path)
        
        if df is None or df.empty:
            print("Error: No data loaded.")
            return None, None
            
        print(f"Total Sequences Generated (Window={WINDOW_SIZE}): {len(df)}")
        train_df, test_df = train_test_split(df, test_size=0.2, shuffle=True, random_state=42)
        print(f"Train: {len(train_df)}, Test: {len(test_df)}")
        return train_df, test_df

    # --- Knowledge Base ---
    def build_knowledge_base(self, train_df):
        print("Building Sequence Knowledge Base...")
        unique_entries = train_df.drop_duplicates(subset=['sequence'])
        print(f"Duplicates removed. Unique sequences: {len(unique_entries)}")
        
        self.kb_sequences = unique_entries['sequence'].tolist()
        self.kb_labels = unique_entries['label'].tolist()
        
        print("Embedding Sequences (this may take longer due to length)...")
        # Sequences are longer, but MiniLM handles up to 256 tokens typically. 5 logs might exceed?
        # A single log is ~30-50 chars. 5 * 50 = 250 chars. Tokens approx 100. Should be fine.
        self.kb_vectors = self.encoder.encode(self.kb_sequences, convert_to_numpy=True, show_progress_bar=True)
        print(f"KB Size: {len(self.kb_vectors)}")

    def save_knowledge_base(self, path):
        try:
            with open(path, 'wb') as f:
                data = {'vectors': self.kb_vectors, 'sequences': self.kb_sequences, 'labels': self.kb_labels}
                pickle.dump(data, f)
            print(f"Sequence KB saved to {path}")
        except Exception as e:
            print(f"Error saving KB: {e}")

    def load_knowledge_base(self, path):
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)
                self.kb_vectors = data['vectors']
                self.kb_sequences = data['sequences']
                self.kb_labels = data['labels']
            print(f"Sequence KB loaded from {path}")
            return True
        except Exception as e:
            print(f"Error loading KB: {e}")
            return False

    # --- Retrieval & Detection ---
    def retrieve(self, query_seq, k=5):
        query_vec = self.encoder.encode([query_seq], convert_to_numpy=True)
        sims = cosine_similarity(query_vec, self.kb_vectors)[0]
        indices = np.argsort(sims)[::-1][:k]
        
        retrieved = []
        for idx in indices:
            retrieved.append({
                'sequence': self.kb_sequences[idx],
                'label': self.kb_labels[idx],
                'similarity': float(sims[idx])
            })
        return retrieved

    async def detect_anomaly(self, query_seq, dry_run=False):
        retrieved = self.retrieve(query_seq)
        
        context_str = "\n".join([
            f"- [{r['label']}] {r['sequence'][:100]}... (Sim: {r['similarity']:.4f})" 
            for r in retrieved
        ])
        
        system_instruction = (
            "You are an expert Cyber Security Analyst.\n"
            "Analyze the following SEQUENCE of Sysmon logs for malicious behavior.\n"
            "The sequence represents a chronological chain of events.\n"
            "Compare the Target Sequence with the Retrieved Reference Sequences from the Knowledge Base.\n"
            "If the sequence matches Known-Normal patterns, classify as 'Normal'.\n"
            "If it shows an attack chain (e.g., unusual parent-child tree, rapid enumeration), classify as 'Malicious'."
        )
        
        user_query = (
            f"Reference Context:\n{context_str}\n\n"
            f"Target Sequence:\n{query_seq}\n\n"
            "Classify as 'Normal' or 'Malicious'."
            "Output Format JSON: {\"classification\": \"...\", \"reasoning\": \"...\"}"
        )

        if dry_run:
            try:
                with open("prompt_log_sequence.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n--- [DRY RUN] ---\nTarget: {query_seq[:100]}...\n{user_query}\n")
            except: pass
            return {"classification": "DryRun", "reasoning": "Log sequence prompt prepared."}

        # API Call logic (Reused from Enhanced)
        payload = {
            "contents": [{"parts": [{"text": user_query}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "generationConfig": {"responseMimeType": "application/json"}
        }
        
        response = await self._call_gemini_api(payload)
        if response and 'candidates' in response:
            try:
                text = response['candidates'][0]['content']['parts'][0]['text']
                return json.loads(text)
            except:
                return {"classification": "Error", "reasoning": "JSON Parse Error"}
        return {"classification": "Error", "reasoning": "No Response"}

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
            except Exception as e:
                if attempt == MAX_RETRIES - 1: return None
                await asyncio.sleep(2 ** attempt)
        return None

    async def evaluate_batch(self, test_df, dry_run=False):
        y_true, y_pred = [], []
        print(f"\n--- Starting Sequence Evaluation (N={len(test_df)}) ---")
        
        for index, row in test_df.iterrows():
            seq = row['sequence']
            label = row['label'] # Case sensitive in DF?
            
            result = await self.detect_anomaly(seq, dry_run=dry_run)
            pred = result.get('classification', 'Error')
            
            y_true.append(1 if str(label).lower() in ['anomaly', 'malicious'] else 0)
            y_pred.append(1 if str(pred).lower() in ['anomaly', 'malicious'] else 0)
            
            print(f"[{index+1}] True: {label} | Pred: {pred} | {result.get('reasoning', '')[:50]}...")
            if not dry_run and self.rpm_limit > 0:
                await asyncio.sleep(60.0 / self.rpm_limit)

        if dry_run: return None
        
        # Metrics
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        print(f"\nResults:\nPrecision: {precision:.4f}\nRecall: {recall:.4f}\nF1: {f1:.4f}")
        return {"precision": precision}
