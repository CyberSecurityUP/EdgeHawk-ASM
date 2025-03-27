import sys
import os
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn

# Corrige path para encontrar arquivos da pasta backend
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "backend")))

# Importa API principal e middleware
from api import app as api_app
from backend.auth_module import AuthMiddleware, router as auth_router

# Cria o app principal
app = FastAPI()

# Middleware de autenticação (carrega request.state.user)
app.add_middleware(AuthMiddleware)

# Inclui as rotas de autenticação
app.include_router(auth_router)

# Inclui todas as rotas da API principal (scan, findings, etc.)
app.mount("/", api_app)

# Inicia o servidor
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
