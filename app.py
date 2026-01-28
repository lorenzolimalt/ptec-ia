from flask import Flask, request, jsonify
import psycopg2
import psycopg2.extras
import requests
import json
import re
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from decimal import Decimal
from datetime import date, datetime, time
import uuid
import logging

app = Flask(__name__)

# ==============================================================================
# CONFIGURAÇÃO E LOGS
# ==============================================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

session = requests.Session()
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IA_URL = "https://mycoach-2.tksol.com.br/v1/chat/completions"
API_KEY = "" 
MODEL_NAME = "llama-4-maverick"

# Whitelist de Tabelas
# LISTA COMPLETA DE TABELAS PERMITIDAS (Baseada no Dump)
ALLOWED_TABLES = {
    # Tabelas Principais
    "auth_user", "seletivo_userdata", "seletivo_address", 
    "seletivo_guardian", "student_data_studentdata",
    
    # Processo Seletivo e Notas
    "seletivo_exam", "seletivo_process", 
    "seletivo_examlocal", "seletivo_examdate", "seletivo_examhour",
    
    # Dados Complementares e Documentos
    "seletivo_registrationdata", "candidate_candidatedocument", 
    "seletivo_academicmeritdocument", "candidate_quota",
    "faq", "tenant_city"
}

# ==============================================================================
# FUNÇÕES UTILITÁRIAS
# ==============================================================================

def get_db_connection():
    return psycopg2.connect(
        host="localhost", 
        database="ptec_db", 
        user="postgres", 
        password="pdinfinita"
    )

def normalize_value(v):
    if isinstance(v, Decimal): return float(v)
    if isinstance(v, (datetime, date)): return v.isoformat()
    if isinstance(v, time): return v.strftime('%H:%M:%S')
    if isinstance(v, uuid.UUID): return str(v)
    return v

def clean_sql(sql_text: str) -> str:
    sql = re.sub(r'```sql|```', '', sql_text, flags=re.IGNORECASE).strip()
    return sql.split(';')[0].strip()

def is_safe_sql(sql: str) -> bool:
    """
    Validação de segurança robusta.
    Remove padrões como EXTRACT(...) antes de validar tabelas para evitar falsos positivos.
    """
    # 1. Normalização básica
    sql_clean = " ".join(sql.split())
    sql_upper = sql_clean.upper()
    
    if not sql_upper.startswith("SELECT"):
        return False
        
    forbidden_cmds = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "GRANT", "EXEC"]
    if any(re.search(rf"\b{cmd}\b", sql_upper) for cmd in forbidden_cmds):
        return False

    # 2. REMOÇÃO DE RUÍDO (EXTRACT, SUBSTRING, ETC) - AQUI ESTÁ A CORREÇÃO
    # Remove trechos como "EXTRACT(MONTH FROM data)" para que o "FROM" dali não confunda o regex
    sql_for_check = re.sub(r"EXTRACT\s*\(.*?\)", "", sql_clean, flags=re.IGNORECASE)
    sql_for_check = re.sub(r"SUBSTRING\s*\(.*?\)", "", sql_for_check, flags=re.IGNORECASE)
    sql_for_check = re.sub(r"TRIM\s*\(.*?\)", "", sql_for_check, flags=re.IGNORECASE)

    # 3. Whitelist de Tabelas
    # Agora buscamos tabelas apenas no SQL limpo (sem os EXTRACTs)
    tables_found = re.findall(r"(?i)\b(?:FROM|JOIN)\s+([a-z0-9_]+)", sql_for_check)
    
    sql_reserved = {'lateral', 'unnest', 'select', 'current_date', 'values', 'distinct'}
    tables_to_validate = [t.lower() for t in tables_found if t.lower() not in sql_reserved]
    
    if not tables_to_validate:
        # Se removeu tudo e não sobrou tabela, algo está errado (ou é SELECT 1)
        # Vamos ser permissivos se não achou nada suspeito, mas idealmente deve ter tabela
        return False 

    for tbl in tables_to_validate:
        if tbl not in ALLOWED_TABLES:
            logger.warning(f"BLOQUEIO DE SEGURANÇA: Tabela '{tbl}' não permitida.")
            return False

    return True

def call_ai_service(messages, temperature=0):
    try:
        payload = {
            "model": MODEL_NAME,
            "messages": messages,
            "temperature": temperature
        }
        response = session.post(IA_URL, json=payload, verify=False, timeout=45)
        
        if response.status_code != 200:
            logger.error(f"Erro API IA (HTTP {response.status_code}): {response.text}")
            return None

        body = response.json()
        
        if 'choices' not in body or not body['choices']:
            logger.error(f"Resposta inválida da IA (sem choices): {body}")
            return None
            
        return body['choices'][0]['message']['content']

    except Exception as e:
        logger.error(f"Exceção fatal na chamada IA: {str(e)}")
        return None

# ==============================================================================
# PROMPT DO SISTEMA
# ==============================================================================

def get_system_prompt(user_id, tenant_id, is_admin, limit_value):
    privacy_filter = f"u.tenant_city_id = '{tenant_id}'"
    if not is_admin:
        privacy_filter += f" AND u.id = {user_id}"

    return f"""
Você é um Motor SQL PostgreSQL 16. Responda APENAS com o código SQL SELECT.

REGRAS OBRIGATÓRIAS QUE VOCÊ NUNCA PODE QUEBRAR:

1. SEMPRE comece o SELECT com:
   SELECT u.first_name, u.last_name, ...
   FROM auth_user u

2. NUNCA gere uma query SELECT sem a cláusula FROM
3. NUNCA omita a tabela auth_user u

[METADADOS]
Data Atual: {datetime.now().strftime('%Y-%m-%d')}
Filtro Obrigatório: WHERE {privacy_filter}
Limite Padrão: LIMIT {limit_value}

[MAPA DO SCHEMA COMPLETO]
Use estes ALIAS e JOINS exatos:

1. auth_user (Alias: u) [TABELA PIVÔ]
   - Colunas: id, first_name, last_name, cpf, social_name, birth_date, email.

2. seletivo_userdata (Alias: ud)
   - Join: LEFT JOIN seletivo_userdata ud ON ud.user_id = u.id
   - Colunas: celphone, nationality, guardian_email.

3. seletivo_guardian (Alias: g) [RESPONSÁVEIS]
   - Join: LEFT JOIN seletivo_guardian g ON g.user_data_id = u.id
   - Colunas: name, relationship (pai/mãe), cellphone, email, cpf.

4. seletivo_address (Alias: a) [ENDEREÇO]
   - Join: LEFT JOIN seletivo_address a ON a.user_id = u.id
   - Colunas: logradouro, numero, bairro, cidade, uf, cep.

5. seletivo_registrationdata (Alias: rd) [SOCIOECONÔMICO]
   - Join: LEFT JOIN seletivo_registrationdata rd ON rd.user_data_id = u.id
   - Colunas: profession, family_income, public_school (boolean), internet_type, pcd.

6. student_data_studentdata (Alias: sd) [DADOS ESCOLARES]
   - Join: LEFT JOIN student_data_studentdata sd ON sd.user_data_id = ud.id
   - Nota: Liga em 'ud', não em 'u'.
   - Colunas: registration (Matrícula), corp_email, status, monitor.

7. candidate_candidatedocument (Alias: cd) [DOCUMENTOS]
   - Join: LEFT JOIN candidate_candidatedocument cd ON cd.user_data_id = ud.id
   - Nota: Liga em 'ud', não em 'u'.
   - Colunas: id_doc_status, address_doc_status, school_history_doc_status (Valores: 'accepted', 'rejected', 'pending').

8. seletivo_exam (Alias: e) [NOTAS]
   - Join: LEFT JOIN seletivo_exam e ON e.user_data_id = u.id
   - Colunas: score, status (aprovado/reprovado), seletivo_process_id.

9. seletivo_process (Alias: p) [PROCESSO SELETIVO]
   - Join: LEFT JOIN seletivo_process p ON e.seletivo_process_id = p.id
   - Colunas: name (Nome do Edital/Processo).

[CAMINHOS ESPECIAIS]
- LOCAL DA PROVA: 
  u -> JOIN seletivo_exam e ON e.user_data_id = u.id 
    -> JOIN seletivo_examhour eh ON e.exam_scheduled_hour_id = eh.id 
    -> JOIN seletivo_examdate ed ON eh.exam_date_id = ed.id 
    -> JOIN seletivo_examlocal el ON ed.local_id = el.id
  (Select: el.name, el.full_address, ed.date, eh.hour).

[DIRETRIZES]
- CONTEXTO DE RETORNO: **SEMPRE** inclua 'u.first_name' e 'u.last_name' (ou 'u.social_name') no SELECT, independentemente do que foi pedido, para identificar de quem são os dados.
- ANIVERSARIANTES: Ignore o ano. Use EXTRACT(MONTH FROM u.birth_date) e EXTRACT(DAY FROM u.birth_date).
- NOMES: Use concatenação (u.first_name || ' ' || u.last_name) ILIKE '%valor%'.
- DOCUMENTOS: Se perguntar "meus documentos", liste os status da tabela 'cd'.
- RESPONSÁVEL: Se perguntar "quem é meu pai/mãe", use a tabela 'g'.
"""

# ==============================================================================
# ROTA PRINCIPAL
# ==============================================================================

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json or {}
    user_msg = data.get("message")
    user_id = data.get("user_id")
    tenant_id = data.get("tenant_city_id")

    if not all([user_msg, user_id, tenant_id]):
        return jsonify({"error": "Parâmetros obrigatórios ausentes"}), 400

    conn = None
    try:
        conn = get_db_connection()
        
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COALESCE(is_superuser, false) OR COALESCE(is_staff, false) 
                FROM auth_user WHERE id = %s
            """, (user_id,))
            res = cur.fetchone()
            is_admin = bool(res[0]) if res else False

        limit_val = 100 if is_admin else 20

        # GERAÇÃO
        prompt = get_system_prompt(user_id, tenant_id, is_admin, limit_val)
        raw_sql = call_ai_service([
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_msg}
        ])

        if not raw_sql:
            return jsonify({"response": "Erro na geração da resposta pela IA."}), 503

        sql = clean_sql(raw_sql)
        logger.info(f"SQL Gerado: {sql}")

        # VALIDAÇÃO SEGURA (FIX EXTRACT)
        if not is_safe_sql(sql):
            logger.warning(f"SQL Bloqueado: {sql}")
            return jsonify({"response": "Consulta bloqueada por segurança."})

        # EXECUÇÃO
        rows = []
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            try:
                cur.execute(sql)
                rows = [dict((k, normalize_value(v)) for k, v in r.items()) for r in cur.fetchall()]
            except psycopg2.Error as db_err:
                logger.error(f"Erro SQL: {db_err}")
                return jsonify({"response": "Erro na execução do SQL."})

        if not rows:
            return jsonify({"response": "Nenhum registro encontrado."})

        # RESUMO
        total_rows = len(rows)
        PREVIEW_LIMIT = 10 # Define quantos aparecem na resposta textual
        is_truncated = total_rows > PREVIEW_LIMIT

        # Preparamos apenas a "fatia" de dados para enviar à IA
        data_context = rows[:PREVIEW_LIMIT]
        
        if is_truncated:
            # PROMPT PARA LISTAS GRANDES
            system_instruction = f"""
            Você é um assistente atencioso. A consulta no banco retornou **{total_rows} registros**, mas você recebeu apenas os **{PREVIEW_LIMIT} primeiros** para economizar leitura.
            
            SUA MISSÃO:
            1. Comece informando o total encontrado de forma clara (ex: "Encontrei 98 candidatos aprovados!").
            2. Avise que está mostrando apenas os primeiros da lista.
            3. Liste os dados fornecidos em Markdown (tabela ou bullet points).
            4. Finalize com uma dica amigável: "Como a lista é longa, se você procura alguém específico, tente digitar o nome dele."
            """
        else:
            # PROMPT PARA LISTAS PEQUENAS (Retorno total)
            system_instruction = f"""
            Você é um assistente útil. A consulta retornou {total_rows} registros.
            Responda à pergunta do usuário apresentando esses dados de forma organizada em português. Seja breve.
            """

        # Chamada Final
        final_response = call_ai_service([
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": f"Pergunta original: {user_msg}\nDados (Amostra): {json.dumps(data_context, ensure_ascii=False)}"}
        ], temperature=0.5)

        return jsonify({
            "response": final_response,
            "data": rows, # O frontend recebe tudo se quiser paginar
            "meta": {"total": total_rows, "truncated": is_truncated, "displayed": len(data_context)}
        })

    except Exception as e:
        logger.error(f"Erro Crítico: {e}")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    app.run(debug=True)