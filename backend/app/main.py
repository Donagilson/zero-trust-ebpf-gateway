from fastapi import FastAPI

app = FastAPI(title="Zero-Trust eBPF Gateway")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
