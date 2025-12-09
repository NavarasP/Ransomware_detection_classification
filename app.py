from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, Sequence, Tuple, runtime_checkable

import json
import tempfile
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from feature_extractor import FEATURE_COLUMNS, compute_md5, extract_features

# Silence Pylance noise for unknown members/vars from third-party stubs
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

if TYPE_CHECKING:  # pragma: no cover
    pass


@runtime_checkable
class EstimatorProtocol(Protocol):
    def predict(self, X: Any) -> Any: ...

    def predict_proba(self, X: Any) -> Any: ...

    @property
    def classes_(self) -> Sequence[Any]: ...

MODEL_PATH = Path("artifacts/random_forest_model.joblib")
META_PATH = Path("artifacts/feature_metadata.json")


@st.cache_resource(show_spinner=False)
def load_model() -> Tuple[EstimatorProtocol, list[str]]:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Model artifact not found. Run `python train_model.py` to train and save the model first."
        )

    loaded: Any = joblib.load(MODEL_PATH)
    model: EstimatorProtocol = loaded  # runtime assumed compatible
    feature_order = FEATURE_COLUMNS
    if META_PATH.exists():
        try:
            meta = json.loads(META_PATH.read_text())
            feature_order = meta.get("feature_columns", FEATURE_COLUMNS)
        except Exception:
            feature_order = FEATURE_COLUMNS
    return model, feature_order


def format_prediction(label: int) -> str:
    return "Benign" if label == 1 else "Ransomware"


def main():
    st.set_page_config(page_title="Ransomware Detector", page_icon="🛡️", layout="centered")
    st.title("Ransomware Detector (Static PE Analysis)")
    st.caption("Upload a Windows PE (.exe) file to predict if it is benign or ransomware.")

    with st.expander("How it works", expanded=False):
        st.markdown(
            """
            - Extracts static header features from the PE file (no execution).
            - Feeds features to a RandomForest model trained on the Kaggle dataset.
            - Outputs a binary label plus model confidence.
            """
        )

    uploaded = st.file_uploader("Upload a PE (.exe) file", type=["exe"])

    if not uploaded:
        st.info("Awaiting file upload.")
        return

    try:
        model, feature_order = load_model()
    except FileNotFoundError as exc:
        st.error(str(exc))
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(uploaded.getbuffer())
        tmp_path = Path(tmp.name)

    try:
        feats = extract_features(tmp_path)
        md5 = compute_md5(tmp_path)
        df = pd.DataFrame([feats])

        missing = [c for c in feature_order if c not in df.columns]
        if missing:
            st.error(f"Extractor missing expected features: {missing}")
            return

        df = df[feature_order]
        prediction = int(model.predict(df)[0])

        proba = None
        if hasattr(model, "predict_proba"):
            classes = list(getattr(model, "classes_", []))
            class_index = classes.index(1) if classes and 1 in classes else 0
            probs = model.predict_proba(df)[0]
            proba = float(probs[class_index]) if probs is not None else None

        st.subheader("Result")
        label_text = format_prediction(prediction)
        if label_text == "Ransomware":
            st.error(f"Prediction: {label_text}")
        else:
            st.success(f"Prediction: {label_text}")

        if proba is not None:
            st.write(f"Confidence (benign class): {proba:.2%}")

        st.write("MD5:", md5)
        st.divider()
        st.write("Extracted features")
        st.dataframe(df.T.rename(columns={0: "value"}))
    except Exception as exc:  # pylint: disable=broad-except
        st.error(f"Failed to score file: {exc}")
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

    st.caption("This tool performs static analysis only; results are for triage, not certification.")


if __name__ == "__main__":
    main()
