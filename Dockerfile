# Usa uma imagem leve do Python (versão 3.10)
FROM python:3.10-slim

# Define labels para identificação da imagem
LABEL maintainer="deploy-bot"
LABEL description="PtecIA Flask Application"

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Define variáveis de ambiente (Formato corrigido: VAR=valor)
# Isso evita avisos de "LegacyKeyValueFormat" durante o build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instala dependências do sistema (gcc para compilação de pacotes python)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Cria um usuário não-root para rodar a aplicação (segurança)
RUN useradd -m -u 1000 appuser

# Copia o arquivo de requirements e instala as dependências
COPY requirements.txt .

# Instala dependências do requirements.txt E o gunicorn explicitamente
# Instalamos o gunicorn separadamente para garantir a existência do binário mesmo se ele faltar no .txt
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# Copia o restante do código da aplicação já definindo o dono (appuser)
# O uso de --chown aqui evita comandos CHOWN separados, otimizando o tamanho da imagem
COPY --chown=appuser:appuser . .

# Troca para o usuário não-root
USER appuser

# Expõe a porta interna do Flask (Padrão 5000)
EXPOSE 5000

# Healthcheck: Verifica se a aplicação está respondendo a cada 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Comando para rodar a aplicação usando Gunicorn
# IMPORTANTE: Substitua 'app:app' pelo seu arquivo:variavel
# Ex: Se seu arquivo é main.py e a instância é application, use 'main:application'
# --access-logfile e --error-logfile com "-" envia logs para o stdout do Docker
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
