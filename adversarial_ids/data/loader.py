"""NSL-KDD dataset loader and preprocessor."""

import os
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

DATASET_URL_TRAIN = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
)
DATASET_URL_TEST = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"
)

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty_level",
]

ATTACK_MAP = {
    "normal": "normal",
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "mailbomb": "dos", "apache2": "dos",
    "processtable": "dos", "udpstorm": "dos",
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe",
    "satan": "probe", "mscan": "probe", "saint": "probe",
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l",
    "multihop": "r2l", "phf": "r2l", "spy": "r2l", "warezclient": "r2l",
    "warezmaster": "r2l", "sendmail": "r2l", "named": "r2l",
    "snmpgetattack": "r2l", "snmpguess": "r2l", "xlock": "r2l",
    "xsnoop": "r2l", "worm": "r2l",
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r",
    "rootkit": "u2r", "httptunnel": "u2r", "ps": "u2r",
    "sqlattack": "u2r", "xterm": "u2r",
}


class NSLKDDLoader:
    """Downloads, preprocesses, and serves the NSL-KDD dataset."""

    def __init__(self, data_dir: str = None, binary: bool = True):
        self.data_dir = Path(data_dir or os.path.join(os.path.dirname(__file__), "raw"))
        self.binary = binary
        self.scaler = MinMaxScaler()
        self.label_encoders: dict[str, LabelEncoder] = {}
        self.feature_names: list[str] = []

    def _download(self, url: str, filename: str) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        filepath = self.data_dir / filename
        if not filepath.exists():
            print(f"[*] Downloading {filename}...")
            urllib.request.urlopen(url)  # noqa: S310 – trusted fixed URL
            urllib.request.urlretrieve(url, filepath)  # noqa: S310
            print(f"[+] Saved to {filepath}")
        return filepath

    def _load_raw(self, path: Path) -> pd.DataFrame:
        df = pd.read_csv(path, header=None, names=COLUMN_NAMES)
        df.drop(columns=["difficulty_level"], inplace=True)
        return df

    def _map_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        df["label"] = df["label"].str.strip().str.lower()
        if self.binary:
            df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
        else:
            df["label"] = df["label"].map(
                lambda x: ATTACK_MAP.get(x, "unknown")
            )
            le = LabelEncoder()
            df["label"] = le.fit_transform(df["label"])
            self.label_encoders["label"] = le
        return df

    def _encode_categoricals(self, df: pd.DataFrame) -> pd.DataFrame:
        categorical = ["protocol_type", "service", "flag"]
        df = pd.get_dummies(df, columns=categorical, dtype=np.float32)
        return df

    def _align_columns(self, train: pd.DataFrame, test: pd.DataFrame):
        missing_in_test = set(train.columns) - set(test.columns)
        missing_in_train = set(test.columns) - set(train.columns)
        for col in missing_in_test:
            test[col] = 0
        for col in missing_in_train:
            train[col] = 0
        test = test[train.columns]
        return train, test

    def load(self) -> dict:
        train_path = self._download(DATASET_URL_TRAIN, "KDDTrain+.txt")
        test_path = self._download(DATASET_URL_TEST, "KDDTest+.txt")

        train_df = self._load_raw(train_path)
        test_df = self._load_raw(test_path)

        train_df = self._map_labels(train_df)
        test_df = self._map_labels(test_df)

        train_df = self._encode_categoricals(train_df)
        test_df = self._encode_categoricals(test_df)

        train_df, test_df = self._align_columns(train_df, test_df)

        y_train = train_df["label"].values
        y_test = test_df["label"].values
        X_train = train_df.drop(columns=["label"]).values.astype(np.float32)
        X_test = test_df.drop(columns=["label"]).values.astype(np.float32)

        self.feature_names = [c for c in train_df.columns if c != "label"]

        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)

        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train, test_size=0.15, random_state=42, stratify=y_train
        )

        return {
            "X_train": X_train.astype(np.float32),
            "y_train": y_train.astype(np.int64),
            "X_val": X_val.astype(np.float32),
            "y_val": y_val.astype(np.int64),
            "X_test": X_test.astype(np.float32),
            "y_test": y_test.astype(np.int64),
            "feature_names": self.feature_names,
            "scaler": self.scaler,
        }
