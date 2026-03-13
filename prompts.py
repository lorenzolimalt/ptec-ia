"""
Prompts e schema do banco de dados — VERSÃO CORRIGIDA.
Corrigido:
- FKs de seletivo_guardian (user_data_id → auth_user.id, não seletivo_userdata)
- FKs de seletivo_exam (user_data_id → auth_user.id)
- FKs de student_data_studentdata (user_data_id → seletivo_userdata.id)
- candidate_quota tem FK duplo: user_id → auth_user.id E user_data_id → seletivo_userdata.id
- JSON enforcement via prefill (técnica mais confiável para Haiku)
"""

from datetime import datetime

# ==============================================================================
# SCHEMA COMPLETO DO BANCO (referência para o LLM) — CORRIGIDO
# ==============================================================================

DATABASE_SCHEMA = """
[SCHEMA DO BANCO — PostgreSQL 16]

─────────────────────────────────────────
TABELA RAIZ: auth_user (alias: u)
─────────────────────────────────────────
Campos: id (INT PK), first_name, last_name, social_name, email (UNIQUE), cpf (UNIQUE),
  username (UNIQUE), cellphone, birth_date (DATE), progress_status (ENUM),
  is_superuser, is_staff, is_active, date_joined (TIMESTAMPTZ), last_login,
  tenant_city_id (FK → tenant_city.id)

progress_status valores possíveis:
  REGISTERED, TWO_AUTH_VALIDATION, CREATING_ADDRESS, CREATING_PERSONA,
  PARTICIPATION_METHOD, CREATING_ENEM_RESULT, CREATING_ACADEMIC_MERIT,
  SCHEDULING_EXAM, WAITING_APPROVE, ENEM_RESULT_REJECTED, ACADEMIC_MERIT_REJECTED,
  STUDENT_EXAM_REJECTED, APPROVED, SIGNING_CONTRACT, CONTRACT_SIGNED, ENROLLED

─────────────────────────────────────────
JOINS A PARTIR DE auth_user (u)
─────────────────────────────────────────

[1] seletivo_userdata (ud)
  FK: ud.user_id → u.id (UNIQUE)
  JOIN: LEFT JOIN seletivo_userdata ud ON ud.user_id = u.id
  Campos: id, cpf, birth_date, social_name, celphone, guardian_email,
          nationality, allowed_city_id

[2] seletivo_address (a)
  FK: a.user_id → u.id
  JOIN: LEFT JOIN seletivo_address a ON a.user_id = u.id
  Campos: id, cep, logradouro, complemento, bairro, cidade, uf, numero

[3] seletivo_persona (sp)
  FK: sp.auth_user_id → u.id (UNIQUE)
  JOIN: LEFT JOIN seletivo_persona sp ON sp.auth_user_id = u.id
  Campos: id, professional_status, experience, experience_duration,
          programming_knowledge_level, motivation_level, project_priority,
          weekly_available_hours, study_commitment, frustration_handling

[4] seletivo_guardian (g)
  ⚠️ FK DIRETO em auth_user: g.user_data_id → u.id  (NÃO passa por seletivo_userdata)
  JOIN: LEFT JOIN seletivo_guardian g ON g.user_data_id = u.id
  Campos: id, relationship, name, cpf, nationality, cellphone, email

[5] seletivo_exam (e)
  ⚠️ FK DIRETO em auth_user: e.user_data_id → u.id  (NÃO passa por seletivo_userdata)
  FK: e.seletivo_process_id → seletivo_process.id
  FK: e.exam_scheduled_hour_id → seletivo_examhour.id
  JOIN: LEFT JOIN seletivo_exam e ON e.user_data_id = u.id
  Campos: id, score (DECIMAL 5,2), status, user_data_id, seletivo_process_id,
          exam_scheduled_hour_id
  UNIQUE: (user_data_id, seletivo_process_id)

[6] enem_enemresult (en)
  FK: en.user_id → u.id
  JOIN: LEFT JOIN enem_enemresult en ON en.user_id = u.id
  Campos: id, inscription_number, name, cpf, foreign_language, languages_score,
          human_sciences_score, natural_sciences_score, math_score, essay_score,
          pdf_file, status, created_at, seletivo_process_id
  UNIQUE: (user_id, seletivo_process_id)

[7] seletivo_academicmeritdocument (amd)
  FK: amd.auth_user_data_id → u.id
  JOIN: LEFT JOIN seletivo_academicmeritdocument amd ON amd.auth_user_data_id = u.id
  Campos: id, document, status, created_at, updated_at, seletivo_process_id
  UNIQUE: (auth_user_data_id, seletivo_process_id)

[8] candidate_quota (cq)
  ⚠️ FK DUPLO:
    cq.user_id → u.id
    cq.user_data_id → ud.id (UNIQUE, pode ser NULL)
  JOIN via auth_user:  LEFT JOIN candidate_quota cq ON cq.user_id = u.id
  Campos: id, quota_doc, quota_doc_status, quota_doc_refuse_reason,
          user_id, user_data_id

[9] tenant_city (tc)
  FK: u.tenant_city_id → tc.id
  JOIN: LEFT JOIN tenant_city tc ON tc.id = u.tenant_city_id
  Campos: id (UUID), name

─────────────────────────────────────────
JOINS A PARTIR DE seletivo_userdata (ud)
Requer: LEFT JOIN seletivo_userdata ud ON ud.user_id = u.id
─────────────────────────────────────────

[10] seletivo_registrationdata (rd)
  FK: rd.user_data_id → ud.id (UNIQUE)
  JOIN: LEFT JOIN seletivo_registrationdata rd ON rd.user_data_id = ud.id
  Campos: id, profession, maritial_status, family_income, education_level,
          pcd, internet_type, public_school (BOOLEAN)

[11] candidate_candidatedocument (cd)
  FK: cd.user_data_id → ud.id (UNIQUE)
  JOIN: LEFT JOIN candidate_candidatedocument cd ON cd.user_data_id = ud.id
  Campos: id, id_doc, id_doc_status, id_doc_refuse_reason,
          address_doc, address_doc_status, address_doc_refuse_reason,
          school_history_doc, school_history_doc_status, school_history_doc_refuse_reason,
          contract_doc, contract_doc_status, contract_doc_refuse_reason, created_at

[12] seletivo_contract (sc)
  FK: sc.user_data_id → ud.id
  JOIN: LEFT JOIN seletivo_contract sc ON sc.user_data_id = ud.id
  Campos: id, status

[13] student_data_studentdata (sd)
  ⚠️ FK: sd.user_data_id → ud.id (UNIQUE)  — passa por seletivo_userdata, NÃO direto em auth_user
  JOIN: LEFT JOIN student_data_studentdata sd ON sd.user_data_id = ud.id
  Campos: id, registration (UNIQUE), corp_email (UNIQUE), equipment_patrimony,
          monitor, "monitorId" (⚠️ CASE-SENSITIVE - USE ASPAS DUPLAS), status

  ⚠️ ATENÇÃO: O campo monitorId é case-sensitive e DEVE ser escrito como sd."monitorId" (com aspas duplas)

[14] seletivo_allowedcity (ac)
  FK: ud.allowed_city_id → ac.id
  JOIN: LEFT JOIN seletivo_allowedcity ac ON ac.id = ud.allowed_city_id
  Campos: id, cidade, uf, active (BOOLEAN), rua, numero, complemento,
          bairro, cnpj, tenant_city_id

─────────────────────────────────────────
CADEIA DE JOINS PARA DADOS DE PROVA
─────────────────────────────────────────
Sempre começa em seletivo_exam (e), JOINado em u:

  LEFT JOIN seletivo_exam e ON e.user_data_id = u.id
  LEFT JOIN seletivo_examhour eh ON eh.id = e.exam_scheduled_hour_id
  LEFT JOIN seletivo_examdate ed ON ed.id = eh.exam_date_id
  LEFT JOIN seletivo_examlocal el ON el.id = ed.local_id

Campos úteis: el.name (local), el.full_address, ed.date (data), eh.hour (hora)

─────────────────────────────────────────
TABELAS DE APOIO (sem JOIN direto em u)
─────────────────────────────────────────

seletivo_process (proc):
  id (UUID PK), name, tenant_city_id (FK → tenant_city.id), createdAt, updatedAt
  JOIN: LEFT JOIN seletivo_process proc ON proc.id = e.seletivo_process_id
        (ou en.seletivo_process_id, amd.seletivo_process_id)

seletivo_examdate (ed): id, date (DATE), local_id, deleted_at
seletivo_examhour (eh): id, hour (TIME), exam_date_id, deleted_at
seletivo_examlocal (el): id, name, full_address, allowed_city_id
"""


# ==============================================================================
# SYSTEM PROMPT PRINCIPAL — CORRIGIDO + PREFILL PARA JSON
# ==============================================================================

def build_system_prompt(user_id: int, tenant_id: str, is_admin: bool, limit_value: int) -> str:
    now = datetime.now()
    current_date_br = now.strftime('%d/%m/%Y')
    current_weekday = ['Segunda-feira','Terça-feira','Quarta-feira','Quinta-feira',
                       'Sexta-feira','Sábado','Domingo'][now.weekday()]

    privacy_filter = (
        "1=1"
        if is_admin
        else f"u.tenant_city_id = '{tenant_id}' AND u.id = {user_id}"
    )
    admin_note = (
        f"ADMIN: pode consultar todos os usuários do banco. Se perguntar de si mesmo (meu, mim, eu), use u.id = {user_id}."
        if is_admin
        else f"USUÁRIO NORMAL: retorne APENAS dados do próprio usuário (seu ID é {user_id})."
    )

    return f"""Você é um assistente especialista em SQL para PostgreSQL 16.
Usuário logado nesta sessão: ID {user_id}.

════════════════════════════════════════
POLÍTICA DE PRIVACIDADE E DADOS (ATENÇÃO!)
════════════════════════════════════════
• Este sistema é SEGURO e o usuário já está AUTENTICADO.
• Você TEM PERMISSÃO TOTAL para exibir CPF, e-mail, data de nascimento e qualquer outro dado sensível do TITULAR da conta (ID {user_id}).
• Se o usuário perguntar "qual o meu...", "me diga meu...", "qual meu CPF?", etc., você DEVE gerar o SQL para buscar essa informação.
• É TERMINANTEMENTE PROIBIDO responder "não posso fornecer informações pessoais" para o próprio usuário sobre seus próprios dados.
• A recusa de fornecer dados do próprio usuário é considerada um erro grave de funcionamento.
• Você só deve recusar informações se o usuário tentar acessar dados de OUTROS usuários (que não seja ele mesmo e não seja admin).

Sua ÚNICA saída permitida é um objeto JSON válido — sem texto antes, sem texto depois, sem markdown.

════════════════════════════════════════
FORMATO DE SAÍDA OBRIGATÓRIO
════════════════════════════════════════
Para perguntas sobre dados do banco:
{{"action":"sql","sql":"SELECT ...","explanation":"frase curta em português"}}

Para saudações, dúvidas gerais ou perguntas fora do banco:
{{"action":"chat","response":"resposta curta em português"}}

Regras absolutas:
• Nunca inclua texto fora do JSON.
• Nunca use blocos markdown (```).
• Nunca repita conteúdo do histórico da conversa.
• Nunca invente tabelas ou colunas — use APENAS o schema abaixo.

════════════════════════════════════════
REGRAS SQL
════════════════════════════════════════
• Tabela raiz obrigatória: FROM auth_user u
• Cláusula WHERE SEMPRE começa com: {privacy_filter}
• Busca por nome: LOWER(COALESCE(u.first_name,'') || ' ' || COALESCE(u.last_name,'') || ' ' || COALESCE(u.social_name,'')) ILIKE '%termo%'
• Sempre finalizar com: LIMIT {limit_value}
• {admin_note}
• Para "meu", "minha", "eu", "mim", use sempre u.id = {user_id} na cláusula WHERE.
• Use LEFT JOIN — nunca INNER JOIN (evita perder registros incompletos).
• Para student_data_studentdata: obrigatório passar por seletivo_userdata primeiro.
• Para seletivo_guardian e seletivo_exam: JOIN direto em auth_user (u.id), NÃO em seletivo_userdata.

⚠️ CAMPOS CASE-SENSITIVE (POSTGRESQL):
• O campo monitorId DEVE ser escrito como sd."monitorId" (com aspas duplas)
• PostgreSQL é case-sensitive quando o campo foi criado com maiúsculas
• NUNCA escreva sd.monitorid (minúsculo) - isso causará erro
• Exemplo CORRETO: SELECT sd."monitorId" FROM student_data_studentdata sd
• Exemplo ERRADO: SELECT sd.monitorid FROM student_data_studentdata sd

════════════════════════════════════════
FORMATO JSON - REGRAS CRÍTICAS
════════════════════════════════════════
- O SQL dentro do campo "sql" DEVE estar em uma ÚNICA LINHA.
- Use espaços simples entre as cláusulas SQL - NUNCA quebre linha.
- Exemplo CORRETO: {{"action":"sql","sql":"SELECT u.id FROM auth_user u WHERE u.id = 1 LIMIT 50","explanation":"..."}}
- Exemplo ERRADO: SQL com \\n ou quebras de linha literais.
- O JSON completo deve ser válido e parseável diretamente.

════════════════════════════════════════
{DATABASE_SCHEMA}
════════════════════════════════════════

Data atual: {current_date_br} ({current_weekday})"""


# ==============================================================================
# PREFILL — TÉCNICA MAIS CONFIÁVEL PARA FORÇAR JSON
# ==============================================================================

def get_assistant_prefill() -> str:
    """
    Retorna o prefill que deve ser enviado como última mensagem com role='assistant'.
    Isso força o modelo a CONTINUAR a partir do '{', garantindo JSON puro.

    Uso na chamada LLM:
        messages = [
            {"role": "system", "content": build_system_prompt(...)},
            *conversa_do_usuario,
            {"role": "assistant", "content": get_assistant_prefill()}  # ← ADICIONAR ISTO
        ]
    """
    return "{"


# ==============================================================================
# PROMPT DE FORMATAÇÃO DE RESPOSTA — sem alterações necessárias
# ==============================================================================

def build_format_prompt(user_msg: str, rows: list, total: int) -> str:
    """Prompt para formatar os dados SQL em linguagem natural."""
    is_single_value = len(rows) == 1 and len(rows[0]) == 1

    if is_single_value:
        single_val = list(rows[0].values())[0]
        return f"""Atue como um assistente direto.

CONTEXTO:
Usuário perguntou: "{user_msg}"
O Banco de Dados respondeu: {single_val}

Responda APENAS com uma frase curta e amigável contextualizando o número.
Exemplos bons: "O total de alunos cadastrados é 16." / "Encontrei 16 registros."
Não use JSON, chaves ou linguagem técnica."""

    import json
    preview = rows[:10]
    return f"""Atue como um assistente prestativo.

CONTEXTO:
Usuário perguntou: "{user_msg}"
Total de registros: {total}
Dados (amostra): {json.dumps(preview, ensure_ascii=False)}

Responda como um Relatório Executivo em Português natural.

REGRAS:
1. Máximo 3 linhas introdutórias antes da lista.
2. Use EXCLUSIVAMENTE o bullet "•" para listar itens — nunca "-" ou "*".
3. Formate datas no padrão brasileiro (DD/MM/AAAA).
4. Se houver muitos registros: "Aqui estão os {min(total, 10)} primeiros de {total}...".
5. Valores ausentes: diga "Não consta" — nunca escreva null, None ou campos vazios.
6. Finalize com uma frase encorajando a próxima pergunta."""