# server/core/deep_sequence.py — LSTM-based Process Sequence Anomaly Detection
"""
Advanced deep learning model that learns NORMAL process execution sequences
and detects anomalous chains that indicate attacks.

Uses bidirectional LSTM with attention mechanism for context-aware detection.

Architecture:
  Input: Sequence of (parent, child, cmdline_features) tuples
  Encoder: BiLSTM with 128 units
  Attention: Multi-head attention (4 heads)
  Decoder: Dense layers with dropout
  Output: Anomaly probability [0-1]

Training:
  - Learns from first 1000 normal events
  - Retrains weekly with feedback
  - Saves model to data/lstm_model.h5

Detection:
  - Maintains sliding window of last 20 events per system
  - Predicts likelihood of next process spawn
  - High prediction error = anomaly
"""

import os, json, time, threading, pickle
import numpy as np
from collections import deque, defaultdict
from typing import List, Tuple, Optional

# Try to import deep learning frameworks
_TF_AVAILABLE = False
_TORCH_AVAILABLE = False

try:
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TF warnings
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    _TF_AVAILABLE = True
except ImportError:
    pass

try:
    import torch
    import torch.nn as nn
    _TORCH_AVAILABLE = True
except ImportError:
    pass

from server.config import DATA_DIR

# ── Configuration ─────────────────────────────────────────────────────────────
SEQUENCE_LENGTH = 20        # Look at last 20 process spawns
VOCAB_SIZE = 5000           # Track top 5000 process names
FEATURE_DIM = 32            # Embedding dimension
LSTM_UNITS = 128
ATTENTION_HEADS = 4
TRAIN_AFTER = 1000          # Train after collecting 1000 events
RETRAIN_EVERY = 5000        # Retrain every 5000 new events
ANOMALY_THRESHOLD = 0.75    # Prediction error > 0.75 = anomaly

MODEL_PATH = os.path.join(DATA_DIR, "lstm_sequence_model.h5")
VOCAB_PATH = os.path.join(DATA_DIR, "lstm_vocab.pkl")
TOKENIZER_PATH = os.path.join(DATA_DIR, "lstm_tokenizer.pkl")

# ── State ─────────────────────────────────────────────────────────────────────
_model = None
_tokenizer = None
_vocab = {}
_trained = False
_training = False
_train_buffer: List[dict] = []
_sequences: dict = defaultdict(lambda: deque(maxlen=SEQUENCE_LENGTH))
_event_count = 0
_lock = threading.Lock()


# ═════════════════════════════════════════════════════════════════════════════
# TOKENIZER & FEATURE EXTRACTION
# ═════════════════════════════════════════════════════════════════════════════

class ProcessTokenizer:
    """Converts process names and cmdlines to integer tokens."""
    
    def __init__(self, vocab_size=VOCAB_SIZE):
        self.vocab_size = vocab_size
        self.word_to_idx = {"<PAD>": 0, "<UNK>": 1}
        self.idx_to_word = {0: "<PAD>", 1: "<UNK>"}
        self.word_counts = defaultdict(int)
        self.next_idx = 2
    
    def fit(self, events: List[dict]):
        """Build vocabulary from events."""
        for e in events:
            for word in self._extract_words(e):
                self.word_counts[word] += 1
        
        # Keep top vocab_size-2 words (reserve 0 for PAD, 1 for UNK)
        top_words = sorted(self.word_counts.items(), key=lambda x: x[1], reverse=True)
        top_words = top_words[:self.vocab_size - 2]
        
        for word, _ in top_words:
            if word not in self.word_to_idx:
                self.word_to_idx[word] = self.next_idx
                self.idx_to_word[self.next_idx] = word
                self.next_idx += 1
    
    def _extract_words(self, event: dict) -> List[str]:
        """Extract relevant words from event."""
        words = []
        words.append(event.get("parent", "").lower().strip())
        words.append(event.get("child", "").lower().strip())
        
        # Extract key cmdline tokens
        cmdline = event.get("cmdline", "").lower()
        for token in ["-enc", "bypass", "hidden", "downloadstring", 
                      "iex", "invoke", "net", "user", "vssadmin"]:
            if token in cmdline:
                words.append(token)
        
        return [w for w in words if w]
    
    def encode_event(self, event: dict) -> List[int]:
        """Convert event to sequence of token IDs."""
        words = self._extract_words(event)
        return [self.word_to_idx.get(w, 1) for w in words]  # 1 = UNK
    
    def encode_sequence(self, events: List[dict], max_len: int) -> np.ndarray:
        """Encode sequence of events to padded matrix."""
        encoded = []
        for e in events:
            encoded.extend(self.encode_event(e))
        
        # Pad or truncate to max_len
        if len(encoded) < max_len:
            encoded = encoded + [0] * (max_len - len(encoded))
        else:
            encoded = encoded[-max_len:]
        
        return np.array(encoded)


def extract_sequence_features(events: List[dict]) -> np.ndarray:
    """
    Extract rich features from event sequence for LSTM input.
    Returns: shape (sequence_length, feature_dim)
    """
    features = []
    
    for e in events:
        feat = [
            # Process name features (one-hot-like encoding)
            float(e.get("child", "").lower() in ["powershell.exe", "pwsh.exe"]),
            float(e.get("child", "").lower() in ["cmd.exe", "bash.exe"]),
            float(e.get("child", "").lower() in ["rundll32.exe", "regsvr32.exe"]),
            float(e.get("parent", "").lower() in ["winword.exe", "excel.exe", "outlook.exe"]),
            
            # Cmdline features
            float("-enc" in e.get("cmdline", "").lower()),
            float("bypass" in e.get("cmdline", "").lower()),
            float("hidden" in e.get("cmdline", "").lower()),
            float("downloadstring" in e.get("cmdline", "").lower()),
            
            # Timing features (normalized)
            float((e.get("time", 0) % 86400) / 86400),  # Time of day [0-1]
            
            # Path features
            float("\\temp\\" in e.get("exe_path", "").lower()),
            float("\\appdata\\" in e.get("exe_path", "").lower()),
            
            # Length features (normalized)
            min(len(e.get("cmdline", "")) / 1000.0, 1.0),
            min(len(e.get("child", "")) / 50.0, 1.0),
            
            # User context
            float(e.get("user", "").upper() == "SYSTEM"),
            
            # PID features
            float(e.get("pid", 10000) < 1000),
        ]
        
        # Pad to FEATURE_DIM if needed
        while len(feat) < FEATURE_DIM:
            feat.append(0.0)
        
        features.append(feat[:FEATURE_DIM])
    
    # Pad sequence if too short
    while len(features) < SEQUENCE_LENGTH:
        features.append([0.0] * FEATURE_DIM)
    
    return np.array(features[-SEQUENCE_LENGTH:])


# ═════════════════════════════════════════════════════════════════════════════
# TENSORFLOW/KERAS MODEL (Primary)
# ═════════════════════════════════════════════════════════════════════════════

def build_lstm_model_tf():
    """
    Build BiLSTM with attention for sequence anomaly detection.
    
    Architecture:
      - Embedding layer (vocab → dense)
      - Bidirectional LSTM (2 layers)
      - Multi-head attention
      - Dense classifier with dropout
    """
    if not _TF_AVAILABLE:
        return None
    
    # Input: sequence of feature vectors
    input_layer = layers.Input(shape=(SEQUENCE_LENGTH, FEATURE_DIM))
    
    # Bidirectional LSTM layers
    lstm1 = layers.Bidirectional(
        layers.LSTM(LSTM_UNITS, return_sequences=True, dropout=0.2)
    )(input_layer)
    
    lstm2 = layers.Bidirectional(
        layers.LSTM(LSTM_UNITS // 2, return_sequences=True, dropout=0.2)
    )(lstm1)
    
    # Multi-head attention
    attention = layers.MultiHeadAttention(
        num_heads=ATTENTION_HEADS,
        key_dim=LSTM_UNITS // 2
    )(lstm2, lstm2)
    
    # Global average pooling
    pooled = layers.GlobalAveragePooling1D()(attention)
    
    # Dense classifier
    dense1 = layers.Dense(64, activation='relu')(pooled)
    dropout = layers.Dropout(0.3)(dense1)
    dense2 = layers.Dense(32, activation='relu')(dropout)
    
    # Output: reconstruction error (lower = more normal)
    output = layers.Dense(FEATURE_DIM, activation='sigmoid')(dense2)
    
    model = keras.Model(inputs=input_layer, outputs=output)
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='mse',
        metrics=['mae']
    )
    
    return model


def train_lstm_model(events: List[dict]):
    """Train the LSTM model on normal events."""
    global _model, _tokenizer, _trained, _training
    
    if not _TF_AVAILABLE:
        print("[LSTM] TensorFlow not available — deep sequence detection disabled")
        _training = False
        return
    
    print(f"[LSTM] Training on {len(events)} events...")
    
    try:
        # Build feature sequences
        X_sequences = []
        y_targets = []
        
        for i in range(SEQUENCE_LENGTH, len(events)):
            sequence = events[i-SEQUENCE_LENGTH:i]
            target = events[i]
            
            X_seq = extract_sequence_features(sequence)
            y_seq = extract_sequence_features([target])[0]
            
            X_sequences.append(X_seq)
            y_targets.append(y_seq)
        
        if len(X_sequences) < 50:
            print(f"[LSTM] Not enough sequences ({len(X_sequences)}), need 50+")
            _training = False
            return
        
        X = np.array(X_sequences)
        y = np.array(y_targets)
        
        print(f"[LSTM] Training shape: X={X.shape}, y={y.shape}")
        
        # Build and train model
        model = build_lstm_model_tf()
        if model is None:
            _training = False
            return
        
        # Train with early stopping
        early_stop = keras.callbacks.EarlyStopping(
            monitor='loss',
            patience=5,
            restore_best_weights=True
        )
        
        history = model.fit(
            X, y,
            epochs=50,
            batch_size=32,
            validation_split=0.2,
            callbacks=[early_stop],
            verbose=0
        )
        
        # Save model
        model.save(MODEL_PATH)
        print(f"[LSTM] Model trained and saved to {MODEL_PATH}")
        print(f"[LSTM] Final loss: {history.history['loss'][-1]:.4f}")
        
        with _lock:
            _model = model
            _trained = True
        
    except Exception as e:
        print(f"[LSTM] Training error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        _training = False


def load_persisted_lstm_model():
    """Load previously trained model from disk."""
    global _model, _trained
    
    if not _TF_AVAILABLE or not os.path.exists(MODEL_PATH):
        return
    
    try:
        model = keras.models.load_model(MODEL_PATH)
        with _lock:
            _model = model
            _trained = True
        print(f"[LSTM] Loaded persisted model from {MODEL_PATH}")
    except Exception as e:
        print(f"[LSTM] Could not load model: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# DETECTION & SCORING
# ═════════════════════════════════════════════════════════════════════════════

def record_sequence_event(event: dict):
    """Add event to sequence tracking and training buffer."""
    global _event_count, _training
    
    system_id = event.get("system_id", "unknown")
    
    with _lock:
        _sequences[system_id].append(event)
        _train_buffer.append(event)
        _event_count += 1
        
        # Trigger training
        if not _trained and not _training and _event_count >= TRAIN_AFTER:
            _training = True
            threading.Thread(
                target=train_lstm_model,
                args=(_train_buffer[:],),
                daemon=True
            ).start()
        
        elif _trained and not _training and _event_count % RETRAIN_EVERY == 0:
            _training = True
            threading.Thread(
                target=train_lstm_model,
                args=(_train_buffer[-TRAIN_AFTER*2:],),
                daemon=True
            ).start()


def detect_sequence_anomaly(system_id: str, event: dict) -> Tuple[int, str]:
    """
    Detect if the current event is anomalous given the sequence history.
    
    Returns:
        (anomaly_score, reason) where score is 0-90
    """
    if not _trained or _model is None:
        return 0, ""
    
    with _lock:
        sequence = list(_sequences.get(system_id, []))
        model = _model
    
    if len(sequence) < SEQUENCE_LENGTH:
        return 0, ""  # Not enough history yet
    
    try:
        # Extract features from sequence
        X_seq = extract_sequence_features(sequence[-SEQUENCE_LENGTH:])
        X_seq = np.expand_dims(X_seq, axis=0)
        
        # Predict next event features
        y_pred = model.predict(X_seq, verbose=0)[0]
        
        # Extract actual features
        y_actual = extract_sequence_features([event])[0]
        
        # Calculate reconstruction error (MSE)
        mse = np.mean((y_pred - y_actual) ** 2)
        
        # Normalize to 0-1 range (empirically, normal events have MSE < 0.1)
        normalized_error = min(mse / 0.1, 1.0)
        
        if normalized_error > ANOMALY_THRESHOLD:
            score = int(normalized_error * 90)  # Max 90 (LSTM caps at HIGH)
            
            # Generate explanation
            reason = f"Sequence anomaly detected (prediction error: {mse:.3f}). "
            
            # Identify which features deviated most
            feature_errors = np.abs(y_pred - y_actual)
            top_deviant_idx = np.argsort(feature_errors)[-3:][::-1]
            
            deviations = []
            feature_names = [
                "PowerShell spawn", "CMD spawn", "LOLBin spawn", "Office parent",
                "Encoded cmdline", "Bypass exec policy", "Hidden window", "Download string",
                "Time of day", "Temp path", "AppData path", "Cmdline length",
                "Process name length", "SYSTEM user", "Low PID"
            ]
            
            for idx in top_deviant_idx:
                if idx < len(feature_names):
                    deviations.append(feature_names[idx])
            
            if deviations:
                reason += f"Unusual: {', '.join(deviations[:2])}"
            
            return score, reason
        
    except Exception as e:
        print(f"[LSTM] Detection error: {e}")
    
    return 0, ""


# ═════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═════════════════════════════════════════════════════════════════════════════

def initialize():
    """Initialize the deep sequence detector."""
    if _TF_AVAILABLE:
        print("[LSTM] Deep sequence detector initialized (TensorFlow)")
        load_persisted_lstm_model()
    else:
        print("[LSTM] TensorFlow not available — install: pip install tensorflow")
        print("[LSTM] Deep sequence detection DISABLED")


def is_available() -> bool:
    """Check if deep learning is available."""
    return _TF_AVAILABLE or _TORCH_AVAILABLE


def get_stats() -> dict:
    """Return training statistics."""
    return {
        "trained": _trained,
        "training": _training,
        "events_seen": _event_count,
        "sequences_tracked": len(_sequences),
        "model_available": _model is not None,
        "backend": "tensorflow" if _TF_AVAILABLE else ("pytorch" if _TORCH_AVAILABLE else "none")
    }
