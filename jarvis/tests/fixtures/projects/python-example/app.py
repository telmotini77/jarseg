from fastapi import FastAPI

app = FastAPI()

def login(name: str) -> str:
    return name
