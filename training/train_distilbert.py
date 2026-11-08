"""
Transformer Fine-Tuning Pipeline for WAF.
Fine-tunes DistilBERT (distilbert-base-uncased) for binary classification
(0 = BENIGN, 1 = MALICIOUS) on HTTP request data.
Uses modern Hugging Face Transformers APIs with PyTorch and class-weighted loss.
"""

import os
import json
import logging
from pathlib import Path
import torch
import torch.nn as nn
import pandas as pd
import numpy as np
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding,
    TrainerCallback
)
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from config.settings import (
    PROCESSED_DATA_DIR,
    TRANSFORMER_MODEL_DIR,
    MODEL_NAME,
    MAX_TOKEN_LENGTH,
    BATCH_SIZE
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_distilbert")

class WAFDataset(Dataset):
    """
    PyTorch Dataset for Tokenized HTTP Request Envelopes.
    """
    def __init__(self, texts, labels, tokenizer, max_length=MAX_TOKEN_LENGTH):
        self.texts = list(texts)
        self.labels = list(labels)
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = int(self.labels[idx])

        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding=False,  # DataCollatorWithPadding dynamically pads to longest in batch
            return_tensors=None
        )

        item = {
            "input_ids": encoding["input_ids"],
            "attention_mask": encoding["attention_mask"],
            "labels": label
        }
        return item

class WeightedLossTrainer(Trainer):
    """
    Custom Trainer that incorporates Class Weights into CrossEntropyLoss
    to prioritize False Negative penalty (penalizing missed attacks).
    """
    def __init__(self, class_weights=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if class_weights is not None:
            self.class_weights = torch.tensor(class_weights, dtype=torch.float)
        else:
            self.class_weights = None

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")

        if self.class_weights is not None:
            loss_fct = nn.CrossEntropyLoss(weight=self.class_weights.to(model.device))
        else:
            loss_fct = nn.CrossEntropyLoss()

        loss = loss_fct(logits.view(-1, self.model.config.num_labels), labels.view(-1))
        return (loss, outputs) if return_outputs else loss

def compute_metrics(eval_pred):
    """
    Computes Accuracy, Precision, Recall, F1, FPR, and FNR for evaluation steps.
    """
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    acc = accuracy_score(labels, preds)
    prec = precision_score(labels, preds, zero_division=0)
    rec = recall_score(labels, preds, zero_division=0)
    f1 = f1_score(labels, preds, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(labels, preds).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr
    }

def train_distilbert_model(
    epochs: int = 2,
    learning_rate: float = 3e-5,
    save_dir: Path = TRANSFORMER_MODEL_DIR,
    quick_demo: bool = False
):
    save_dir.mkdir(parents=True, exist_ok=True)

    train_path = PROCESSED_DATA_DIR / "train.csv"
    val_path = PROCESSED_DATA_DIR / "val.csv"
    test_path = PROCESSED_DATA_DIR / "test.csv"

    if not train_path.exists():
        raise FileNotFoundError(f"Missing train data at {train_path}. Run build_dataset.py first.")

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    if quick_demo:
        logger.info("Quick demo mode enabled: subsampling dataset for fast local verification...")
        train_df = train_df.sample(n=min(400, len(train_df)), random_state=42)
        val_df = val_df.sample(n=min(100, len(val_df)), random_state=42)
        test_df = test_df.sample(n=min(100, len(test_df)), random_state=42)

    logger.info(f"Loaded {len(train_df)} train, {len(val_df)} val, {len(test_df)} test samples.")

    # Calculate class weights: heavier weight on malicious class (label=1) to suppress false negatives
    class_counts = train_df["label"].value_counts().to_dict()
    total = len(train_df)
    weight_0 = total / (2.0 * class_counts.get(0, 1))
    weight_1 = (total / (2.0 * class_counts.get(1, 1))) * 1.25  # +25% penalty on missed attacks
    class_weights = [weight_0, weight_1]
    logger.info(f"Calculated class weights: Benign (0)={weight_0:.3f}, Malicious (1)={weight_1:.3f}")

    # Load Tokenizer & Model
    logger.info(f"Loading pretrained model and tokenizer: {MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2,
        id2label={0: "BENIGN", 1: "MALICIOUS"},
        label2id={"BENIGN": 0, "MALICIOUS": 1}
    )

    train_dataset = WAFDataset(train_df["normalized_text"], train_df["label"], tokenizer)
    val_dataset = WAFDataset(val_df["normalized_text"], val_df["label"], tokenizer)
    test_dataset = WAFDataset(test_df["normalized_text"], test_df["label"], tokenizer)

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"Using training device: {device}")

    # Training Arguments (compatible with modern transformers)
    training_args = TrainingArguments(
        output_dir=str(save_dir / "checkpoints"),
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=learning_rate,
        per_device_train_batch_size=BATCH_SIZE if device == "cuda" else 8,
        per_device_eval_batch_size=BATCH_SIZE if device == "cuda" else 8,
        num_train_epochs=epochs,
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=20,
        save_total_limit=1,
        report_to="none"
    )

    trainer = WeightedLossTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
        class_weights=class_weights
    )

    logger.info("Starting DistilBERT fine-tuning...")
    trainer.train()

    # Final Evaluation on unseen test set
    logger.info("Running evaluation on unseen test set...")
    eval_results = trainer.evaluate(test_dataset)
    logger.info(f"Test Set Metrics: {eval_results}")

    # Save final model and tokenizer
    logger.info(f"Saving fine-tuned model and tokenizer to {save_dir}...")
    trainer.save_model(str(save_dir))
    tokenizer.save_pretrained(str(save_dir))

    # Save evaluation summary
    metrics_path = save_dir / "distilbert_metrics.json"
    clean_metrics = {k.replace("eval_", ""): float(v) for k, v in eval_results.items() if isinstance(v, (int, float))}
    clean_metrics["model"] = "DistilBERT (Fine-tuned)"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(clean_metrics, f, indent=2)

    logger.info(f"Metrics saved to {metrics_path}")
    print("\n" + "="*60)
    print("DISTILBERT TRAINING COMPLETE")
    print("="*60)
    print(f"Accuracy:  {clean_metrics.get('accuracy', 0):.4f}")
    print(f"Precision: {clean_metrics.get('precision', 0):.4f}")
    print(f"Recall:    {clean_metrics.get('recall', 0):.4f}")
    print(f"F1-Score:  {clean_metrics.get('f1', 0):.4f}")
    print(f"FNR:       {clean_metrics.get('fnr', 0):.4f}")
    print(f"FPR:       {clean_metrics.get('fpr', 0):.4f}")
    print("="*60 + "\n")

    return save_dir

if __name__ == "__main__":
    train_distilbert_model()
