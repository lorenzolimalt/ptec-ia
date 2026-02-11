import os
import re
import json
import time
import uuid
import logging
import hashlib
import redis
import jwt
import psycopg2
import psycopg2.extras
import requests
from psycopg2 import pool
from decimal import Decimal
from datetime import date, datetime
from functools import wraps
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# ==============================================================================
# 1. CONFIGURAÇÃO INICIAL E AMBIENTE
# ==============================================================================
load_dotenv()
app = Flask(__name__)

# Logs estruturados
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s'
)
logger = logging.getLogger("SQLBot")

# Desabilita warnings de SSL inseguro (apenas se necessário, ideal é corrigir o certificado)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurações de Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# Configurações de IA
IA_URL = "https://mycoach-2.tksol.com.br/v1/chat/completions"
MODEL_NAME = "llama-4-maverick"
IA_TIMEOUT = 45

# Configurações de Banco de Dados (Connection Pool)
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "pd_backoffice")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "asdd")
MIN_CONN = 1
MAX_CONN = 20

# Criação do Pool de Conexões (Crucial para performance)
try:
    pg_pool = psycopg2.pool.ThreadedConnectionPool(
        MIN_CONN, MAX_CONN,
        host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS
    )
    logger.info("Connection Pool do PostgreSQL iniciado com sucesso.")
except Exception as e:
    logger.critical(f"Falha ao criar Pool de Conexão: {e}")
    exit(1)

# Configurações JWT
JWT_SECRET = os.getenv("JWT_SECRET", "default_secret_change_me")
JWT_ALGORITHM = "HS256"

# Rate Limiting
RATE_LIMIT_WINDOW = 10
RATE_LIMIT_MAX = 5

# Whitelist de Tabelas (Segurança)
ALLOWED_TABLES = {
    "auth_user", "seletivo_userdata", "seletivo_address", 
    "seletivo_guardian", "student_data_studentdata",
    "seletivo_exam", "seletivo_process", 
    "seletivo_examlocal", "seletivo_examdate", "seletivo_examhour",
    "seletivo_registrationdata", "candidate_candidatedocument", 
    "seletivo_academicmeritdocument", "candidate_quota",
    "faq", "tenant_city"
}

# ==============================================================================
# 2. FUNÇÕES UTILITÁRIAS E SEGURANÇA
# ==============================================================================

def get_db_connection():
    """Obtém conexão do Pool."""
    return pg_pool.getconn()

def release_db_connection(conn):
    """Devolve conexão ao Pool."""
    if conn:
        pg_pool.putconn(conn)

def normalize_value(v):
    if isinstance(v, Decimal): return float(v)
    if isinstance(v, (datetime, date)): return v.isoformat()
    if isinstance(v, uuid.UUID): return str(v)
    return v

def clean_sql(sql_text: str) -> str:
    """Limpa formatação Markdown do SQL."""
    sql = re.sub(r'```sql|```', '', sql_text, flags=re.IGNORECASE).strip()
    return sql.split(';')[0].strip() # Remove múltiplos comandos

def is_safe_sql(sql: str, tenant_id: str, is_admin: bool) -> bool:
    """Validação de segurança para impedir comandos destrutivos."""
    sql_clean = " ".join(sql.split())
    sql_upper = sql_clean.upper()
    
    if not sql_upper.startswith("SELECT"):
        return False
        
    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "GRANT", "EXEC", "pg_sleep"]
    if any(re.search(rf"\b{cmd}\b", sql_upper) for cmd in forbidden):
        return False

    if not is_admin:
        # Verifica se o tenant_id do usuário aparece no WHERE do SQL
        if f"'{tenant_id}'" not in sql:
            logger.warning(f"⛔ BLOQUEIO: Tentativa de burlar filtro de tenant. SQL: {sql}")
            return False

    # Remove funções inofensivas para verificar tabelas
    check_sql = re.sub(r"(EXTRACT|SUBSTRING|TRIM|COALESCE)\s*\(.*?\)", "", sql_clean, flags=re.IGNORECASE)
    
    tables_found = re.findall(r"(?i)\b(?:FROM|JOIN)\s+([a-z0-9_]+)", check_sql)
    sql_reserved = {'lateral', 'unnest', 'select', 'current_date', 'values', 'distinct', 'as', 'on', 'where', 'limit', 'group', 'order', 'left', 'right', 'inner', 'outer', 'join'}
    
    tables_to_validate = [t.lower() for t in tables_found if t.lower() not in sql_reserved]
    
    if not tables_to_validate:
        return False 

    for tbl in tables_to_validate:
        if tbl not in ALLOWED_TABLES:
            logger.warning(f"⛔ BLOQUEIO: Tabela '{tbl}' não permitida.")
            return False

    return True

# Configuração da Sessão HTTP com Retry
session = requests.Session()
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))

def call_ai_service(messages, temperature=0.1):
    """Chamada robusta à API de IA."""
    try:
        payload = {
            "model": MODEL_NAME,
            "messages": messages,
            "temperature": temperature
        }
        # Verify=False apenas se o certificado do mycoach for auto-assinado. 
        # Em prod, tente resolver o certificado e usar verify=True.
        response = session.post(IA_URL, json=payload, verify=False, timeout=IA_TIMEOUT)
        
        if response.status_code != 200:
            logger.error(f"Erro API IA: {response.status_code} - {response.text}")
            return None

        body = response.json()
        return body['choices'][0]['message']['content']

    except Exception as e:
        logger.error(f"Exceção na chamada IA: {str(e)}")
        return None

def classify_intent(user_msg):
    """
    Analisa se a mensagem requer uma consulta SQL ao banco de dados.
    Retorna: True (é SQL) ou False (é papo furado/ajuda/data atual).
    """
    
    # 1. Regra rápida para saudações curtas (economia de token)
    greetings = ['oi', 'olá', 'bom dia', 'boa tarde', 'boa noite', 'ajuda', 'help', 'quem é você']
    if user_msg.lower().strip() in greetings:
        return False

    # 2. Análise via IA
    prompt = f"""
    Atue como um classificador de intenção. Analise a mensagem do usuário.
    Responda APENAS com um JSON válido: {{"is_sql": true}} ou {{"is_sql": false}}.

    Regras:
    - Se o usuário pedir dados, contagens, listas, informações de cadastro -> is_sql: true
    - Se o usuário cumprimentar, perguntar data/hora atual, pedir ajuda, ou falar de coisas fora do contexto de 'sistema de gestão' -> is_sql: false
    - "Que dia é hoje?" -> is_sql: false (isso é conhecimento geral)
    - "Qual a data da prova?" -> is_sql: true (isso é dado do banco)

    Mensagem: "{user_msg}"
    """
    
    response = call_ai_service([{"role": "system", "content": prompt}], temperature=0.0)
    
    try:
        # Tenta limpar markdown caso a IA coloque ```json
        clean_resp = response.replace("```json", "").replace("```", "").strip()
        data = json.loads(clean_resp)
        return data.get("is_sql", True) # Na dúvida, assume que é SQL
    except:
        return True # Fallback seguro

def execute_sql_with_autocorrect(conn, initial_sql, user_msg, system_prompt_base):
    """
    Tenta executar o SQL. Se der erro no Postgres, devolve o erro para a IA
    e pede uma correção (máximo de 2 tentativas de correção).
    """
    current_sql = initial_sql
    max_retries = 2 
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            # TENTATIVA DE EXECUÇÃO
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(current_sql)
                # Se funcionar, converte e retorna
                rows = [dict((k, normalize_value(v)) for k, v in r.items()) for r in cur.fetchall()]
                
                # Se corrigiu, logamos para monitoria
                if attempt > 0:
                    logger.info(f"✅ SQL Auto-corrigido com sucesso na tentativa {attempt}")
                
                return rows, current_sql

        except psycopg2.Error as db_err:
            # OBRIGATÓRIO: Fazer rollback para limpar a transação falha
            conn.rollback()
            last_error = db_err
            
            if attempt == max_retries:
                logger.error(f"❌ Falha Final após {max_retries} tentativas. Erro: {db_err}")
                break # Sai do loop e vai lançar o erro
            
            logger.warning(f"⚠️ Erro SQL (Tentativa {attempt+1}/{max_retries + 1}): {db_err}. Solicitando correção à IA...")

            # --- PROMPT DE CORREÇÃO (A Mágica) ---
            # Passamos o histórico: Prompt Original + Pergunta + SQL Errado + Mensagem de Erro
            repair_messages = [
                {"role": "system", "content": system_prompt_base},
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": current_sql},
                {"role": "user", "content": f"ERRO CRÍTICO NO BANCO: {db_err}\n\nAnalise o erro. Corrija a sintaxe SQL imediatamente. Retorne APENAS o SQL corrigido, sem explicações."}
            ]

            # Chama a IA com temperatura 0 (máxima precisão)
            fixed_sql_raw = call_ai_service(repair_messages, temperature=0.0)
            
            if not fixed_sql_raw:
                break # Se a IA cair, para tudo

            current_sql = clean_sql(fixed_sql_raw)

            # Validação de segurança novamente (vai que a IA alucina um DROP na correção)
            if not is_safe_sql(current_sql):
                logger.warning("⛔ Correção gerou SQL inseguro. Abortando.")
                break

    # Se saiu do loop, falhou
    raise last_error

# ==============================================================================
# 3. GESTÃO DE ESTADO (REDIS)
# ==============================================================================

def rate_limit(tenant_id: str, user_id: int):
    key = f"rate:chat:{tenant_id}:{user_id}"
    current = redis_client.incr(key)
    if current == 1:
        redis_client.expire(key, RATE_LIMIT_WINDOW)
    return current <= RATE_LIMIT_MAX

def get_user_is_admin(user_id: int):
    """Verifica se é admin com cache."""
    cache_key = f"user:admin:{user_id}"
    cached = redis_client.get(cache_key)
    if cached: return cached == "1"

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(is_superuser, false) OR COALESCE(is_staff, false) FROM auth_user WHERE id = %s", (user_id,))
            res = cur.fetchone()
            is_admin = bool(res[0]) if res else False
    finally:
        release_db_connection(conn)

    redis_client.setex(cache_key, 300, "1" if is_admin else "0")
    return is_admin

def get_user_name_from_db(user_id):
    """Busca o nome do usuário para dar contexto à IA no chat geral."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT first_name FROM auth_user WHERE id = %s", (user_id,))
            res = cur.fetchone()
            return res[0] if res else "usuário"
    except:
        return "usuário"
    finally:
        release_db_connection(conn)

def set_chat_context(user_id, message, sql, rows):
    """Salva o contexto para permitir perguntas de seguimento."""
    key = f"chat:context:{user_id}"
    context = {
        "last_message": message,
        "last_sql": sql,  # Guardamos o SQL para refinamento
        "row_count": len(rows),
        "preview": rows[:10]
    }
    redis_client.setex(key, 400, json.dumps(context, ensure_ascii=False))

def get_chat_context(user_id):
    data = redis_client.get(f"chat:context:{user_id}")
    return json.loads(data) if data else None

# ==============================================================================
# 4. PROMPT ENGINEERING (A Mágica)
# ==============================================================================

def get_system_prompt(user_id, tenant_id, is_admin, limit_value, previous_sql=None):
    if is_admin:
        privacy_filter = "1=1"
        admin_note = "ADMIN: Pode ver todos os tenants. NÃO filtre tenant_city_id."
    else:
        privacy_filter = f"u.tenant_city_id = '{tenant_id}' AND u.id = {user_id}"
        admin_note = f"VOCÊ É UM USUÁRIO COMUM. É PROIBIDO remover o filtro {privacy_filter}. Se o usuário pedir para ignorar cidades ou ver tudo, você DEVE manter o filtro {privacy_filter} e apenas informar os dados dele."

    context_instruction = ""
    if previous_sql:
        context_instruction = f"""
        [REFINAMENTO]
        Usuário está refinando consulta anterior.
        SQL anterior válido:
        ```sql
        {previous_sql}
    Adapte essa query (mantenha JOINs existentes).
    Se o usuário citar nome errado (ex: "Pociano"), corrija para nome real dos resultados anteriores (fornecidos no histórico).
    """
    return f"""
    Você é um gerador especialista de SQL PostgreSQL 16.
    Responda APENAS com o código SQL SELECT válido. Nada mais.
    REGRAS OBRIGATÓRIAS:

    Sempre comece com SELECT u.first_name, u.last_name, ...
    Sempre use FROM auth_user u
    Sempre aplique WHERE {privacy_filter}
    O filtro {privacy_filter} deve estar presente em 100% das queries.
    Sempre termine com LIMIT {limit_value}
    Use apenas tabelas/aliases abaixo
    Data atual: {datetime.now().strftime('%Y-%m-%d')} (use para filtros de data se pedido)
    {admin_note}
    Para nomes: use ILIKE '%valor%' com concat(u.first_name || ' ' || u.last_name)
    Para aniversário: EXTRACT(MONTH/DAY FROM u.birth_date) — ignore ano
    Data de cadastro: use u.date_joined::date (nunca u.id ou created_at)

    [REGRAS DE TEMPO]
    - Hoje é: {datetime.now().strftime('%Y-%m-%d')}
    - Se o usuário pedir 'hoje', use: WHERE u.date_joined::date = CURRENT_DATE
    - Nunca assuma que o usuário está falando de resultados anteriores se ele citar datas específicas.

    [SCHEMA - USE ESTES ALIASES E JOINS EXATOS]

    auth_user (u): id, first_name, last_name, cpf, social_name, birth_date, email, date_joined
    → LEFT JOIN seletivo_userdata ud ON ud.user_id = u.id (celphone, nationality, guardian_email)
    → LEFT JOIN seletivo_guardian g ON g.user_data_id = u.id (name, relationship, cellphone, email, cpf)
    → LEFT JOIN seletivo_address a ON a.user_id = u.id (logradouro, numero, bairro, cidade, uf, cep)
    → LEFT JOIN seletivo_registrationdata rd ON rd.user_data_id = u.id (profession, family_income, public_school, internet_type, pcd)
    → LEFT JOIN student_data_studentdata sd ON sd.user_data_id = ud.id (registration, corp_email, status, monitor)
    → LEFT JOIN candidate_candidatedocument cd ON cd.user_data_id = ud.id (id_doc_status, address_doc_status, school_history_doc_status)
    → LEFT JOIN seletivo_exam e ON e.user_data_id = u.id (score, status, seletivo_process_id)

    [LOCAL DA PROVA]
    e → LEFT JOIN seletivo_examhour eh ON e.exam_scheduled_hour_id = eh.id
    → LEFT JOIN seletivo_examdate ed ON eh.exam_date_id = ed.id
    → LEFT JOIN seletivo_examlocal el ON ed.local_id = el.id
    (selecione el.name, el.full_address, ed.date, eh.hour)
    Sempre inclua u.first_name e u.last_name no SELECT para identificação.
    {context_instruction}
    """

# ==============================================================================
# 5. ROTA PRINCIPAL (CHAT)
# ==============================================================================

# Decorator de Autenticação
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "Token ausente"}), 401
        try:
            token = auth.split(" ")[1]
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_sub": False})
            request.user = {
                "user_id": payload.get("sub"),
                "tenant_city_id": payload.get("tenant_city_id"),
                "roles": payload.get("roles", [])
            }
        except Exception:
            return jsonify({"error": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/chat", methods=["POST"])
@jwt_required
def chat():
    data = request.json or {}
    user_msg = data.get("message")
    user_id = request.user["user_id"]
    tenant_id = request.user["tenant_city_id"]

    if not user_msg:
        return jsonify({"error": "Mensagem vazia"}), 400

    is_sql_request = classify_intent(user_msg)
    log_status = "SQL_QUERY" if is_sql_request else "GENERAL_CHAT"
    logger.info(f"🔍 [INTENT_CLASSIFIED] User: {user_id} | Is_SQL: {is_sql_request} | Type: {log_status} | Message: '{user_msg[:100]}...'")

    if not is_sql_request:
        user_name = get_user_name_from_db(user_id)
        # Preparação da Data em Português (Para não depender do locale do servidor)
        dias_semana = ['Segunda-feira', 'Terça-feira', 'Quarta-feira', 'Quinta-feira', 'Sexta-feira', 'Sábado', 'Domingo']
        agora = datetime.now()
        dia_semana_str = dias_semana[agora.weekday()]
        data_str = agora.strftime('%d/%m/%Y')
        hora_str = agora.strftime('%H:%M')

        # Prompt Blindado Temporalmente
        sys_prompt = f"""
        [INFORMAÇÕES DO USUÁRIO]
        - Nome do usuário: {user_name} (ID: {user_id})
        - Tenant ID: {tenant_id}

        [INSTRUÇÃO DE TEMPO REAL - PRIORIDADE MÁXIMA]
        Você deve IGNORAR sua data de corte de treinamento ou qualquer data interna.
        A Verdade Absoluta do Sistema agora é:
        - Data: {data_str}
        - Dia da Semana: {dia_semana_str}
        - Hora: {hora_str}

        Se o usuário perguntar "que dia é hoje", responda EXATAMENTE com os dados acima.
        NÃO tente calcular dias passados ou futuros baseados em outros anos.
        NÃO mencione que você é uma IA treinada em 2023/2024. Aceite que estamos em 2026.

        [INSTRUÇÃO DE CONTEXTO]
        Se o usuário perguntar "quem sou eu" ou "qual meu nome", responda que ele é {user_name} APENAS, nao cite ID ou Tenant ID.
        Você deve agir de forma prestativa.
        
        Responda de forma curta, prestativa e natural.
        """
        
        chat_response = call_ai_service([
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_msg}
        ], temperature=0.3) # Temperatura baixa para reduzir criatividade na data

        return jsonify({
            "response": chat_response,
            "data": [],
            "meta": {"type": "chat_general"}
        })

    if not rate_limit(tenant_id, user_id):
        return jsonify({"error": "Muitas requisições. Aguarde."}), 429

    # Recupera contexto (se houver) para entender "follow-up questions"
    context = get_chat_context(user_id)
    context_keywords = ["quantos", "total", "quem eram", "qual foi", "resultado anterior", "lista que me deu"]
    is_asking_about_context = any(word in user_msg.lower() for word in context_keywords)

    if is_asking_about_context and context:
        logger.info(f"💡 Respondendo via Contexto (User {user_id})")
        
        # Usamos uma temperatura baixa para a IA apenas comentar o que já está no Redis
        history_prompt = f"""
        O usuário está perguntando sobre o resultado da última consulta.
        DADOS DA ÚLTIMA CONSULTA:
        - Pergunta anterior: "{context.get('last_message')}"
        - Total encontrado no banco: {context.get('row_count')}
        - Amostra dos dados: {json.dumps(context.get('preview'), ensure_ascii=False)}

        Pergunta atual do usuário: "{user_msg}"

        Responda de forma natural e direta baseando-se APENAS nos dados acima.
        Se ele perguntar 'quantos', diga o número total.
        """
        
        context_response = call_ai_service([{"role": "system", "content": history_prompt}], temperature=0.2)
        
        return jsonify({
            "response": context_response,
            "data": context.get("preview"),
            "meta": {
                "total": context.get("row_count"),
                "source": "cache_context"
            }
        })

    # Lógica de conexão segura
    conn = get_db_connection()
    try:
        is_admin = get_user_is_admin(user_id)
        limit_val = 50 if is_admin else 20
        previous_sql = context.get("last_sql") if context else None

        prompt = get_system_prompt(user_id, tenant_id, is_admin, limit_val, previous_sql)
        
        messages = [{"role": "system", "content": prompt}]
        if context and previous_sql:
            # Pegamos os dados do contexto
            prev_data_str = json.dumps(context.get('preview', []), ensure_ascii=False)
            
            # Injetamos como uma memória do assistente ou user
            messages.append({
                "role": "user", 
                "content": f"""
                Resultado da minha busca anterior ({context['row_count']} registros encontrados). 
                Aqui estão os dados que você retornou:
                {prev_data_str}
                
                Query que gerou isso: {context['last_sql']}
                """
            })
        
        messages.append({"role": "user", "content": user_msg})

        if len(json.dumps(messages)) > 8000:  # estimativa grosseira de bytes ≈ tokens
            # Versão ultra-slim sem preview completo
            messages = [{"role": "system", "content": prompt},
                        {"role": "user", "content": user_msg}]

        raw_sql = call_ai_service(messages)
        if not raw_sql:
            return jsonify({"response": "Serviço de IA indisponível temporariamente."}), 503

        sql = clean_sql(raw_sql)
        logger.info(f"SQL Gerado Inicial (User {user_id}): {sql}")

        if not is_safe_sql(sql, tenant_id, is_admin):
            logger.warning(f"SQL Bloqueado: {sql}")
            return jsonify({"response": "Não posso executar essa consulta por motivos de segurança."})

        sql_hash = hashlib.sha256(sql.encode()).hexdigest()
        cache_key_sql = f"sql:cache:{tenant_id}:{sql_hash}"
        cached_rows = redis_client.get(cache_key_sql)

        if cached_rows:
            logger.info("CACHE HIT")
            rows = json.loads(cached_rows)
            final_sql = sql
        else:
            logger.info("CACHE MISS - Iniciando Execução com Retry")
            # CAMADA 3: AUTO-CORREÇÃO DE ERRO SQL
            try:
                # Chama a função blindada que tenta corrigir o SQL se der erro
                rows, final_sql = execute_sql_with_autocorrect(conn, sql, user_msg, prompt)
                
                # Se passou, salva no cache
                redis_client.setex(cache_key_sql, 60, json.dumps(rows, ensure_ascii=False))

            except psycopg2.Error as e:
                # Se falhou após todos os retries
                return jsonify({
                    "response": "Encontrei uma dificuldade técnica ao cruzar esses dados. Tente simplificar a pergunta.",
                    "debug_error": str(e)
                })

        # Atualiza o contexto com o SQL FINAL (pode ser diferente do inicial se houve correção)
        set_chat_context(user_id, user_msg, final_sql, rows)

        if not rows:
            return jsonify({"response": "Não encontrei nenhum registro para sua busca.", "data": []})

        data_preview = rows[:10]
        total = len(rows)

        summary_prompt = f"""
        Atue como um assistente de dados objetivo e responda de forma clara, concisa e amigável.
        
        CONTEXTO:
        O usuário perguntou: "{user_msg}"
        O banco retornou: {total} registros no total.
        Abaixo estão os dados (limitados para visualização):
        {json.dumps(data_preview, ensure_ascii=False)}
        Evite jargões técnicos (ex.: Encontramos ... no banco de dados | De acordo com as colunas no banco de dados...).

        INSTRUÇÕES DE RESPOSTA:
        1. Se houver apenas 1 resultado, confirme o nome da pessoa (ex: "Encontrei as notas do Douglas...") e responda o dado principal que ele pediu.
        2. Seja extremamente conciso. Evite listas com asteriscos se puder falar em uma frase natural.
        3. Se o nome no banco for um pouco diferente do que o usuário digitou (ex: Dougla -> Douglas), mencione o nome correto para confirmar.
        4. NUNCA use frases como "Encontramos registros relacionados" ou "Abaixo estão os dados".
        5. Não repita informações técnicas como IDs ou timestamps, a menos que solicitado.

        Exemplo de tom: "Encontrei a nota do Douglas Marcone. Ele está com status pendente e nota 26.0."
        
        Seja sucinto.
        """
        
        final_text = call_ai_service([{"role": "user", "content": summary_prompt}], temperature=0.3)

        return jsonify({
            "response": final_text,
            "data": rows,
            "meta": {"total": total, "displayed": len(data_preview)}
        })

    except psycopg2.Error as db_err:
        logger.error(f"Erro SQL: {db_err}")
        # Retorno amigável se a IA errar coluna
        return jsonify({"response": "Tive uma confusão interna ao buscar os dados. Tente reformular a pergunta."})
    except Exception as e:
        logger.error(f"Erro Geral: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        release_db_connection(conn)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)