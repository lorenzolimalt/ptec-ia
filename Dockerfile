# Usa uma imagem leve do Python (versão 3.10, pode ajustar se necessário)
FROM python:3.10-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Define variáveis de ambiente para evitar que o Python crie arquivos .pyc
# e garante que os logs sejam exibidos no stdout (útil para 'docker logs')
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Instala dependências do sistema (se necessário, como libgcc para alguns pacotes)
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Copia o arquivo de requirements e instala as dependências
# Fazemos isso antes de copiar o resto para aproveitar o cache do Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do código da aplicação para dentro do container
COPY . .

# Cria um usuário não-root para rodar a aplicação (boas práticas de segurança)
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expõe a porta interna do Flask (Padrão 5000)
EXPOSE 5000

# Comando para rodar a aplicação usando Gunicorn
# IMPORTANTE: Substitua 'app:app' pelo seu arquivo:variavel
# Ex: Se seu arquivo é main.py e a instância é application, use 'main:application'
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
