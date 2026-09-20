import json
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions

from core.config import REPORTS_DIR

CHROMA_PATH = REPORTS_DIR / "rag_chroma_db"


class VectorStore:
    def __init__(self, collection_name: str = "knowledge_base", ephemeral: bool = False):
        if ephemeral:
            self.client = chromadb.EphemeralClient()
        else:
            CHROMA_PATH.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(path=str(CHROMA_PATH))

        self.ef = embedding_functions.DefaultEmbeddingFunction()
        self.collection_name = collection_name
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            embedding_function=self.ef,
            metadata={"hnsw:space": "cosine"},
        )

    def add_documents(self, documents: list[dict]) -> int:
        if not documents:
            return 0

        ids = [d["id"] for d in documents]
        texts = [d["text"] for d in documents]
        metadatas = [d.get("metadata", {"source": "unknown"}) for d in documents]

        # chromadb requires string values in metadata
        metadatas = [
            {k: str(v) for k, v in m.items()} for m in metadatas
        ]

        self.collection.add(ids=ids, documents=texts, metadatas=metadatas)
        return len(documents)

    def query(self, query_text: str, n_results: int = 3) -> list[dict]:
        count = self.collection.count()
        if count == 0:
            return []

        results = self.collection.query(
            query_texts=[query_text],
            n_results=min(n_results, count),
        )

        docs = []
        for i, doc_id in enumerate(results["ids"][0]):
            docs.append(
                {
                    "id": doc_id,
                    "text": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i]
                    if results.get("distances")
                    else None,
                }
            )
        return docs

    def reset(self):
        self.client.delete_collection(self.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=self.ef,
            metadata={"hnsw:space": "cosine"},
        )

    def count(self) -> int:
        return self.collection.count()

    def load_from_json(self, path: str | Path) -> int:
        with open(path) as f:
            docs = json.load(f)
        return self.add_documents(docs)
