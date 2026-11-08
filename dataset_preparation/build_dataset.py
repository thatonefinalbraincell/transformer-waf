"""
Master dataset builder for the Transformer-Based WAF.
Combines raw data sources, applies security normalization,
deduplicates, balances classes, and generates stratified splits.
"""

import json
import logging
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

from config.settings import RAW_DATA_DIR, PROCESSED_DATA_DIR, DATA_DIR
from dataset_preparation.payload_collector import generate_synthetic_dataset
from dataset_preparation.csic_parser import csic_parser

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("build_dataset")

def build_waf_dataset(num_curated_samples: int = 6000, random_state: int = 42):
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)

    records = []

    # 1. Parse CSIC 2010 if raw files exist in data/raw
    anomalous_file = RAW_DATA_DIR / "anomalousRequest.txt"
    normal_file = RAW_DATA_DIR / "normalRequest.txt"

    if anomalous_file.exists():
        logger.info(f"Parsing CSIC anomalous requests from {anomalous_file}...")
        csic_attacks = csic_parser.parse_file(anomalous_file, label=1, attack_type="malicious")
        records.extend(csic_attacks)
        logger.info(f"Loaded {len(csic_attacks)} CSIC attack samples.")

    if normal_file.exists():
        logger.info(f"Parsing CSIC normal requests from {normal_file}...")
        csic_normal = csic_parser.parse_file(normal_file, label=0, attack_type="benign")
        records.extend(csic_normal)
        logger.info(f"Loaded {len(csic_normal)} CSIC benign samples.")

    # 2. Add high-entropy curated / synthesized attack and benign requests
    logger.info(f"Generating {num_curated_samples} curated real-world payload samples...")
    curated = generate_synthetic_dataset(num_samples=num_curated_samples)
    records.extend(curated)
    logger.info(f"Loaded {len(curated)} curated samples.")

    df = pd.DataFrame(records)
    initial_count = len(df)

    # 3. Data Cleaning & Deduplication
    # Remove nulls in normalized_text
    df = df.dropna(subset=["normalized_text"])
    # Deduplicate on normalized_text to prevent train-test data leakage
    df = df.drop_duplicates(subset=["normalized_text"]).reset_index(drop=True)
    dedup_count = len(df)
    logger.info(f"Deduplication: Reduced {initial_count} -> {dedup_count} samples ({initial_count - dedup_count} duplicates removed).")

    # 4. Stratified Train / Val / Test Split (70% / 15% / 15%)
    # We stratify across the composite class (label + attack_type) to maintain exact attack proportions
    df["stratify_col"] = df["label"].astype(str) + "_" + df["attack_type"]

    train_df, temp_df = train_test_split(
        df,
        test_size=0.30,
        random_state=random_state,
        stratify=df["stratify_col"]
    )

    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=random_state,
        stratify=temp_df["stratify_col"]
    )

    # Drop temporary stratify column
    train_df = train_df.drop(columns=["stratify_col"])
    val_df = val_df.drop(columns=["stratify_col"])
    test_df = test_df.drop(columns=["stratify_col"])

    # 5. Export Processed Datasets
    train_path = PROCESSED_DATA_DIR / "train.csv"
    val_path = PROCESSED_DATA_DIR / "val.csv"
    test_path = PROCESSED_DATA_DIR / "test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    logger.info(f"Train split saved to: {train_path} ({len(train_df)} samples)")
    logger.info(f"Validation split saved to: {val_path} ({len(val_df)} samples)")
    logger.info(f"Test split saved to: {test_path} ({len(test_df)} samples)")

    # 6. Export Sample Test Requests for API verification
    sample_items = []
    for _, row in test_df.groupby("attack_type").head(3).iterrows():
        sample_items.append({
            "method": row["method"],
            "path": row["path"],
            "params": row["params"],
            "body": row["body"],
            "normalized_text": row["normalized_text"],
            "expected_label": int(row["label"]),
            "attack_type": row["attack_type"]
        })

    sample_json_path = DATA_DIR / "sample_requests.json"
    with open(sample_json_path, "w", encoding="utf-8") as f:
        json.dump(sample_items, f, indent=2)
    logger.info(f"Sample requests catalog exported to: {sample_json_path}")

    # Print Distribution Summary
    print("\n" + "="*50)
    print("DATASET CLASS DISTRIBUTION SUMMARY")
    print("="*50)
    print(df["attack_type"].value_counts())
    print("\nBinary Label Distribution:")
    print(df["label"].value_counts(normalize=True).map(lambda n: f"{n:.2%}"))
    print("="*50 + "\n")

    return train_path, val_path, test_path

if __name__ == "__main__":
    build_waf_dataset()
