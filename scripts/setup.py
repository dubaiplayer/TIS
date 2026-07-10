"""
Idempotent setup for autonomous / agent use.

Ensures Python deps and the trained model exist, then prints a final status line:
  READY     — ML classifier available (full analyzer).
  DEGRADED  — no model and no source data; analyzer runs RULES-ONLY (still works).

Safe to re-run: it no-ops when already READY. The `phishing-email-analyzer` skill
calls this once before analyzing.

Run:  .venv/Scripts/python.exe -m scripts.setup
"""
import importlib.util
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ensure_deps():
    """Install requirements only if a core import is missing (fast on re-run)."""
    core = {"pandas": "pandas", "numpy": "numpy", "sklearn": "scikit-learn",
            "joblib": "joblib", "pyarrow": "pyarrow", "bs4": "beautifulsoup4",
            "yaml": "pyyaml", "spellchecker": "pyspellchecker", "pydantic": "pydantic"}
    missing = [pip_name for mod, pip_name in core.items()
               if importlib.util.find_spec(mod) is None]
    if missing:
        print(f"Installing dependencies (missing: {', '.join(sorted(set(missing)))}) ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                               "-r", os.path.join(ROOT, "requirements.txt")])
    else:
        print("Dependencies present.")


def main():
    ensure_deps()

    model_path = os.path.join(ROOT, "models", "classifier.joblib")
    train_parquet = os.path.join(ROOT, "data", "processed", "trackA_train.parquet")

    if os.path.exists(model_path):
        print("READY: trained model present — ML signal enabled.")
        return 0

    # Import project modules lazily (after deps are guaranteed).
    from phishing_analyzer import classifier, data_prep

    if os.path.exists(train_parquet):
        print("Processed data found; training classifier ...")
        classifier.train()
        print("READY: model trained from existing processed data.")
        return 0

    # Try to build data from the raw source corpus, if it's present.
    from scripts import build_enron_raw
    have_raw_enron = os.path.exists(build_enron_raw.SRC)
    have_sources = os.path.exists(os.path.join(data_prep.DATA_DIR, "CEAS_08.csv"))
    if have_raw_enron and have_sources:
        print("Source corpus found; building processed data + training ...")
        build_enron_raw.main()
        data_prep.main()
        classifier.train()
        print("READY: dataset built and model trained.")
        return 0

    print("DEGRADED: no trained model and the source corpus was not found at "
          f"'{data_prep.DATA_DIR}'.")
    print("  -> The analyzer will run RULES-ONLY (12 attributes, no ML classifier).")
    print("  -> To enable the ML signal: place the phishing corpus (CEAS_08.csv, "
          "Ling.csv, Nazario.csv, Nigerian_Fraud.csv, SpamAssasin.csv) and the raw "
          "Enron 'emails.csv' in that folder, then re-run: python -m scripts.setup")
    return 0


if __name__ == "__main__":
    sys.exit(main())
