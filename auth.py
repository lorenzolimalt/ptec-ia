"""
Módulo de autenticação e autorização.
JWT decorator, verificação de admin, rate limiting.
"""
import logging
import datetime
from typing import Dict, Any, Optional
from functools import wraps

import jwt as pyjwt
from flask import request, jsonify

from config import JWT_SECRET, JWT_ALGORITHM, RATE_LIMIT_WINDOW, RATE_LIMIT_MAX, redis_client
from database import get_db_connection, release_db_connection

logger = logging.getLogger("SQLBot")

# ==============================================================================
# TOKEN GENERATION & VALIDATION
# ==============================================================================

def generate_tokens(user_id: Any, tenant_city_id: Any, roles: list = None) -> Dict[str, str]:
    """Gera um par de tokens (Access e Refresh) compatível com o backend principal."""
    access_payload = {
        "sub": str(user_id),
        "tenant_city_id": str(tenant_city_id) if tenant_city_id else None,
        "roles": roles or [],
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1) # 1 hora de access
    }
    
    refresh_payload = {
        "sub": str(user_id),
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7) # 7 dias de refresh
    }
    
    access_token = pyjwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    refresh_token = pyjwt.encode(refresh_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "access": access_token,
        "refresh": refresh_token
    }

def validate_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    """Valida o refresh token e retorna o payload."""
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception as e:
        logger.error(f"Refresh Token inválido: {e}")
        return None


# ==============================================================================
# JWT DECORATOR
# ==============================================================================

def jwt_required(f):
    """Decorator que exige e decodifica token JWT do header Authorization."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({
                "detail": "Token ausente",
                "code": "token_not_valid"
            }), 401
        try:
            token = auth.split(" ")[1]
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_sub": False})
            logger.info(f"Token decodificado com sucesso: {payload}")
            request.user = {
                "user_id": payload.get("sub"),
                "tenant_city_id": payload.get("tenant_city_id"),
                "roles": payload.get("roles", []),
            }
        except pyjwt.ExpiredSignatureError:
            return jsonify({
                "detail": "Token expirado",
                "code": "token_not_valid"
            }), 401
        except pyjwt.InvalidTokenError:
            return jsonify({
                "detail": "Token inválido",
                "code": "token_not_valid"
            }), 401
        except Exception:
            return jsonify({
                "detail": "Erro ao processar token",
                "code": "token_not_valid"
            }), 401
        return f(*args, **kwargs)
    return decorated


# ==============================================================================
# HELPERS
# ==============================================================================

def rate_limit(tenant_id: str, user_id: int) -> bool:
    """Retorna True se o usuário está dentro do rate limit."""
    key = f"rate:chat:{tenant_id}:{user_id}"
    current = redis_client.incr(key)
    if current == 1:
        redis_client.expire(key, RATE_LIMIT_WINDOW)
    return current <= RATE_LIMIT_MAX


def get_user_is_admin(user_id: int, roles: list = None) -> bool:
    """Verifica se o usuário é admin (via flags no DB ou roles no Token)."""
    # 1. Verifica Roles do Token primeiro (mais rápido)
    admin_roles = ['ADMIN', 'ADMIN_MASTER' 'SUPERUSER', 'staff', 'superuser']
    if roles:
        if any(role.upper() in [r.upper() for r in admin_roles] for role in roles):
            logger.info(f"Usuário {user_id} reconhecido como ADMIN via Roles do Token.")
            return True

    # 2. Verifica Cache Redis
    cache_key = f"user:admin:{user_id}"
    cached = redis_client.get(cache_key)
    if cached is not None:
        return cached == "1"

    # 3. Verifica Banco de Dados
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(is_superuser, false) OR COALESCE(is_staff, false) FROM auth_user WHERE id = %s",
                (user_id,)
            )
            res = cur.fetchone()
            is_admin = bool(res[0]) if res else False
            logger.info(f"Checagem DB para usuário {user_id}: is_admin={is_admin}")
    except Exception as e:
        logger.error(f"Erro ao verificar se usuário {user_id} é admin: {e}")
        is_admin = False
    finally:
        if conn:
            release_db_connection(conn)

    redis_client.setex(cache_key, 300, "1" if is_admin else "0")
    return is_admin


def get_user_name(user_id: int) -> str:
    """Busca o primeiro nome do usuário no banco."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT first_name FROM auth_user WHERE id = %s", (user_id,))
            res = cur.fetchone()
            return res[0] if res else "usuário"
    except Exception:
        return "usuário"
    finally:
        release_db_connection(conn)
