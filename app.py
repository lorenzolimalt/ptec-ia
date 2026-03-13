"""
PtecIA — Assistente inteligente de consulta ao banco de dados.
Ponto de entrada: define Flask app, CORS e rotas.
Toda a lógica está nos módulos: config, database, auth, memory, llm, prompts.
"""
import json
import logging

import psycopg2
from flask import Flask, request, jsonify
from flask_cors import CORS

from config import pg_pool
from database import get_db_connection, release_db_connection, clean_sql, is_safe_sql, execute_with_cache
from auth import jwt_required, rate_limit, get_user_is_admin, get_user_name, validate_refresh_token, generate_tokens, get_db_connection, release_db_connection
from memory import add_message, build_llm_messages, clear_history
from llm import call_ai_service, route_and_respond, format_response
from prompts import build_system_prompt, build_format_prompt

# ==============================================================================
# APP INIT
# ==============================================================================

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

logger = logging.getLogger("SQLBot")

# ==============================================================================
# ROTA PRINCIPAL — /chat
# ==============================================================================

@app.route("/chat", methods=["POST"])
@jwt_required
def chat():
    data = request.json or {}
    user_msg = data.get("message")
    user_id = request.user["user_id"]
    tenant_id = request.user["tenant_city_id"]
    
    logger.info(f"--- DEBUG CHAT ---")
    logger.info(f"User ID from Token: {user_id} (type: {type(user_id)})")
    logger.info(f"Tenant ID from Token: {tenant_id}")
    logger.info(f"Message: {user_msg}")

    if not user_msg:
        return jsonify({"error": "Mensagem vazia"}), 400

    # Rate limiting
    if not rate_limit(tenant_id, user_id):
        return jsonify({"error": "Muitas requisições. Aguarde."}), 429

    # ──────────────────────────────────────────────────────────
    # 1. Construir mensagens com histórico conversacional
    #    O LLM recebe TUDO e decide sozinho (sem keywords!)
    # ──────────────────────────────────────────────────────────
    user_roles = request.user.get("roles", [])
    is_admin = get_user_is_admin(user_id, roles=user_roles)
    limit_val = 50 if is_admin else 20
    
    logger.info(f"Final is_admin status for user {user_id}: {is_admin}")

    system_prompt = build_system_prompt(user_id, tenant_id, is_admin, limit_val)
    messages = build_llm_messages(system_prompt, user_id, user_msg)

    # Salva a mensagem do usuário no histórico
    add_message(user_id, "user", user_msg)

    # ──────────────────────────────────────────────────────────
    # 2. Chamada ÚNICA ao LLM (classificação + resposta/SQL)
    # ──────────────────────────────────────────────────────────
    result = route_and_respond(messages)

    if not result:
        return jsonify({"response": "Serviço de IA indisponível temporariamente."}), 503

    action = result.get("action", "chat")

    # ──────────────────────────────────────────────────────────
    # 3A. AÇÃO: Chat geral (saudação, ajuda, etc.)
    # ──────────────────────────────────────────────────────────
    if action == "chat":
        response_text = result.get("response", "Olá! Como posso ajudar?")

        # Salva resposta no histórico
        add_message(user_id, "assistant", response_text)

        return jsonify({
            "response": response_text,
            "data": [],
            "meta": {"type": "chat_general"}
        })

    # ──────────────────────────────────────────────────────────
    # 3B. AÇÃO: SQL — Executar consulta no banco
    # ──────────────────────────────────────────────────────────
    raw_sql = result.get("sql", "")
    sql = clean_sql(raw_sql)
    logger.info(f"SQL Gerado (User {user_id}): {sql} | Pergunta: {user_msg}")

    # Validação de segurança
    if not is_safe_sql(sql, tenant_id, user_id, is_admin):
        error_msg = "Consulta não permitida por segurança."
        add_message(user_id, "assistant", error_msg)
        return jsonify({"response": error_msg})

    # Execução com cache + auto-correção
    conn = get_db_connection()
    try:
        try:
            rows, final_sql = execute_with_cache(
                conn, sql, user_msg, system_prompt, tenant_id, is_admin, call_ai_service
            )
        except psycopg2.Error as e:
            error_msg = "Não consegui cruzar esses dados corretamente. Tente ser mais específico."
            add_message(user_id, "assistant", error_msg)
            return jsonify({
                "response": error_msg,
                "debug_error": str(e)
            })

        if not rows:
            no_data_msg = "Nenhum dado encontrado para sua busca."
            add_message(user_id, "assistant", no_data_msg, sql=final_sql, row_count=0)
            return jsonify({"response": no_data_msg, "data": []})

        # ──────────────────────────────────────────────────────
        # 4. Formatar resposta em linguagem natural
        # ──────────────────────────────────────────────────────
        total = len(rows)
        fmt_prompt = build_format_prompt(user_msg, rows, total)
        final_text = format_response(fmt_prompt)

        # Salva resposta + SQL no histórico conversacional
        add_message(user_id, "assistant", final_text, sql=final_sql, row_count=total)

        return jsonify({
            "response": final_text,
            "data": rows,
            "meta": {"total": total}
        })

    except Exception as e:
        logger.error(f"Erro Geral no Chat: {e}")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        release_db_connection(conn)


# ==============================================================================
# ROTA — /chat/reset
# ==============================================================================

@app.route("/chat/reset", methods=["POST"])
@jwt_required
def reset_chat():
    user_id = request.user["user_id"]
    clear_history(user_id)
    return jsonify({"status": "success", "message": "Contexto limpo"}), 200


# ==============================================================================
# ROTA — /auth/refresh
# ==============================================================================

@app.route("/auth/refresh", methods=["POST"])
def refresh_token():
    """Rota para renovar o accessToken usando um refreshToken."""
    data = request.json or {}
    refresh_token = data.get("refresh")
    
    if not refresh_token:
        return jsonify({"error": "Refresh token ausente"}), 400
        
    payload = validate_refresh_token(refresh_token)
    if not payload:
        return jsonify({"error": "Token inválido ou expirado"}), 401
        
    user_id = payload.get("sub")
    
    # Para gerar um novo access completo, precisamos do tenant_id do banco
    conn = get_db_connection()
    tenant_id = None
    roles = []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT tenant_city_id, is_superuser, is_staff FROM auth_user WHERE id = %s", (user_id,))
            res = cur.fetchone()
            if res:
                tenant_id = res[0]
                if res[1]: roles.append("superuser")
                if res[2]: roles.append("staff")
    finally:
        release_db_connection(conn)
        
    # Gera novos tokens
    new_tokens = generate_tokens(user_id, tenant_id, roles)
    
    return jsonify(new_tokens), 200


# ==============================================================================
# HEALTHCHECK
# ==============================================================================

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ==============================================================================
# ENTRYPOINT
# ==============================================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)