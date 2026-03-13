"""
Módulo de banco de dados.
Connection pool, execução segura de SQL, validação de segurança, e auto-correção.
"""
import re
import uuid
import hashlib
import json
import logging
from decimal import Decimal
from datetime import date, datetime

import psycopg2
import psycopg2.extras

from config import pg_pool, redis_client, ALLOWED_TABLES

logger = logging.getLogger("SQLBot")

# ==============================================================================
# CONEXÕES
# ==============================================================================

def get_db_connection():
    """Obtém conexão do Pool com validação simples."""
    conn = pg_pool.getconn()
    try:
        # Verifica se a conexão ainda está ativa
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        return conn
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        logger.warning("🔄 Conexão do pool estava inativa. Tentando obter uma nova...")
        try:
            conn.close()
        except:
            pass
        # Aqui o ideal seria remover do pool, mas pg_pool.getconn() pode retornar a mesma se não for tratada.
        # Recriamos a conexão manualmente para garantir.
        import psycopg2
        from config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS
        return psycopg2.connect(
            host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASS
        )


def release_db_connection(conn):
    """Devolve conexão ao Pool."""
    if conn:
        pg_pool.putconn(conn)


# ==============================================================================
# UTILITÁRIOS
# ==============================================================================

def normalize_value(v):
    """Converte tipos do Postgres para JSON-serializáveis."""
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    return v


def clean_sql(sql_text: str) -> str:
    """Remove formatação Markdown e múltiplos comandos do SQL."""
    sql = re.sub(r'```sql|```', '', sql_text, flags=re.IGNORECASE).strip()
    return sql.split(';')[0].strip()


# ==============================================================================
# VALIDAÇÃO DE SEGURANÇA
# ==============================================================================

def is_safe_sql(sql: str, tenant_id: str, user_id: int, is_admin: bool) -> bool:
    """Valida se o SQL é seguro: somente SELECT, tabelas permitidas, filtro de tenant."""
    sql_clean = " ".join(sql.split())
    sql_upper = sql_clean.upper()

    if not sql_upper.startswith("SELECT"):
        return False

    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "GRANT", "EXEC", "pg_sleep"]
    if any(re.search(rf"\b{cmd}\b", sql_upper) for cmd in forbidden):
        return False

    if not is_admin:
        # Permite se tiver o filtro de tenant OU o filtro específico do ID do usuário logado
        uid_str = str(user_id)
        has_tenant_filter = f"'{tenant_id}'" in sql
        
        # Verifica u.id = 4276, u.id = '4276', etc.
        user_id_patterns = [
            f"u.id = {uid_str}", f"u.id={uid_str}",
            f"u.id = '{uid_str}'", f"u.id='{uid_str}'"
        ]
        has_user_id_filter = any(p in sql for p in user_id_patterns)
        
        if not (has_tenant_filter or has_user_id_filter):
            logger.warning(f"⛔ BLOQUEIO: Tentativa de burlar filtro de acesso (Tenant: {tenant_id}, User: {user_id}). SQL: {sql}")
            return False

    # Remove funções inofensivas para verificar tabelas
    check_sql = re.sub(r"(EXTRACT|SUBSTRING|TRIM|COALESCE)\s*\(.*?\)", "", sql_clean, flags=re.IGNORECASE)

    tables_found = re.findall(r"(?i)\b(?:FROM|JOIN)\s+([a-z0-9_]+)", check_sql)
    sql_reserved = {
        'lateral', 'unnest', 'select', 'current_date', 'values', 'distinct',
        'as', 'on', 'where', 'limit', 'group', 'order', 'left', 'right',
        'inner', 'outer', 'join'
    }

    tables_to_validate = [t.lower() for t in tables_found if t.lower() not in sql_reserved]

    if not tables_to_validate:
        return False

    for tbl in tables_to_validate:
        if tbl not in ALLOWED_TABLES:
            logger.warning(f"⛔ BLOQUEIO: Tabela '{tbl}' não permitida.")
            return False

    return True


# ==============================================================================
# EXECUÇÃO COM AUTO-CORREÇÃO
# ==============================================================================

def execute_sql_with_autocorrect(conn, initial_sql, user_msg, system_prompt_base, tenant_id, is_admin, call_ai_fn):
    """
    Tenta executar o SQL. Se der erro, solicita correção ao LLM (até 2 tentativas).
    Recebe `call_ai_fn` como dependência para evitar import circular.
    """
    current_sql = initial_sql
    max_retries = 2
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(current_sql)
                rows = [dict((k, normalize_value(v)) for k, v in r.items()) for r in cur.fetchall()]

                if attempt > 0:
                    logger.info(f"✅ SQL Auto-corrigido com sucesso na tentativa {attempt}")

                return rows, current_sql

        except psycopg2.Error as db_err:
            conn.rollback()
            last_error = db_err

            if attempt == max_retries:
                logger.error(f"❌ Falha Final após {max_retries} tentativas. Erro: {db_err}")
                break

            logger.warning(f"⚠️ Erro SQL (Tentativa {attempt+1}/{max_retries + 1}): {db_err}. Solicitando correção à IA...")

            repair_messages = [
                {"role": "system", "content": system_prompt_base},
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": current_sql},
                {"role": "user", "content": f"ERRO CRÍTICO NO BANCO: {db_err}\n\nAnalise o erro. Corrija a sintaxe SQL imediatamente. Retorne APENAS o SQL corrigido, sem explicações."}
            ]

            fixed_sql_raw = call_ai_fn(repair_messages, temperature=0.0)
            if not fixed_sql_raw:
                break

            current_sql = clean_sql(fixed_sql_raw)

            if not is_safe_sql(current_sql, tenant_id, is_admin):
                logger.warning("⛔ Correção gerou SQL inseguro. Abortando.")
                break

    raise last_error


# ==============================================================================
# EXECUÇÃO COM CACHE
# ==============================================================================

def execute_with_cache(conn, sql, user_msg, system_prompt, tenant_id, is_admin, call_ai_fn):
    """
    Executa SQL com cache Redis de 60s e auto-correção.
    Retorna (rows, final_sql).
    """
    sql_hash = hashlib.sha256(sql.encode()).hexdigest()
    cache_key = f"sql:cache:{tenant_id}:{sql_hash}"
    cached = redis_client.get(cache_key)

    if cached:
        return json.loads(cached), sql

    rows, final_sql = execute_sql_with_autocorrect(
        conn, sql, user_msg, system_prompt, tenant_id, is_admin, call_ai_fn
    )
    redis_client.setex(cache_key, 60, json.dumps(rows, ensure_ascii=False))
    return rows, final_sql
