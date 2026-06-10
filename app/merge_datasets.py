import pandas as pd
from pathlib import Path

DATASET_FILE = Path("dataset.csv")
RULE_OUTPUT_FILE = Path("rule_outputs.csv")
OUT_FILE = Path("merged_dataset.csv")

def main():
    features = pd.read_csv(DATASET_FILE)
    rules = pd.read_csv(RULE_OUTPUT_FILE)

    #Making sure that runs is in int so that join works properly
    features["run"] = features["run"].astype(int)
    rules["run"] = rules["run"].astype(int)

    merged = features.merge (
        rules,
        on=["scenario", "run"],
        how="left",
        suffixes=("", "_rule")
    )

    merged.to_csv(OUT_FILE, index=False)
    print(f"Saved merged dataset to {OUT_FILE}")
    print(f"Merged columns: ", merged.columns.tolist())

if __name__ == "__main__":
    main()