"""
CES Dashboard — Backend
FastAPI + SQLite + JWT
"""
import os, io, sqlite3, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from contextlib import contextmanager

import bcrypt as _bcrypt
import pandas as pd
from fastapi import (
    FastAPI, Depends, HTTPException, UploadFile, File,
    status, Query, Response
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM   = "HS256"
TOKEN_HOURS = int(os.getenv("TOKEN_HOURS", "12"))
DB_PATH     = os.getenv("DB_PATH", "/data/ces.db")   # Railway volume
ADMIN_USER  = os.getenv("ADMIN_USER", "admin")
# bcrypt tiene límite de 72 bytes — truncamos por si la contraseña es larga
ADMIN_PASS  = os.getenv("ADMIN_PASS", "Ces2026")[:72]

# Columnas requeridas en el Excel consolidado
REQUIRED_COLS = {
    "TIPO", "PERIODO", "FECHA_REF", "MES_PRESTACION",
    "DESFASE_MESES", "ANIO_ANTERIOR",
    "LOTE", "CLINICA", "NomClinica", "MUTUAL", "NomMutual",
    "PRACTICA", "NomPractica", "ITEM", "FECHA", "CANTIDAD",
    "CUENTA", "NomCuenta", "IMPORTE", "LIQUIDA",
    "AFILIADO", "NOM_AFI", "DOCUMENTO", "DIAG", "USUARIO",
}

# ─────────────────────────────────────────────────────────────
# DB HELPERS
# ─────────────────────────────────────────────────────────────
def get_db_path() -> str:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return DB_PATH

@contextmanager
def db_conn():
    conn = sqlite3.connect(get_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with db_conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            nombre    TEXT NOT NULL,
            hash_pass TEXT NOT NULL,
            rol       TEXT NOT NULL CHECK(rol IN ('admin','directorio','interno','prestador')),
            activo    INTEGER NOT NULL DEFAULT 1,
            creado    TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS permisos (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            clinica_id INTEGER NOT NULL,
            nom_clinica TEXT NOT NULL,
            UNIQUE(usuario_id, clinica_id)
        );

        CREATE TABLE IF NOT EXISTS prestaciones (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            periodo         TEXT NOT NULL,
            tipo            TEXT NOT NULL,
            fecha_ref       TEXT,
            mes_prestacion  TEXT,
            desfase_meses   INTEGER,
            anio_anterior   TEXT,
            lote            TEXT,
            clinica         INTEGER,
            nom_clinica     TEXT,
            mutual          INTEGER,
            nom_mutual      TEXT,
            practica        INTEGER,
            nom_practica    TEXT,
            subcodigo       TEXT,
            item            INTEGER,
            fecha           TEXT,
            cantidad        REAL,
            cuenta          TEXT,
            nom_cuenta      TEXT,
            importe         REAL,
            liquida         REAL,
            imp2            REAL,
            efector         TEXT,
            nom_efector     TEXT,
            matricula       TEXT,
            mat_efector     TEXT,
            afiliado        TEXT,
            documento       TEXT,
            nom_afi         TEXT,
            sexo            TEXT,
            edad            INTEGER,
            diag            TEXT,
            autoriza        TEXT,
            arancela        TEXT,
            pasa            TEXT,
            refactura       TEXT,
            formula         TEXT,
            sucformula      TEXT,
            fechapres       TEXT,
            deriva          TEXT,
            usuario_carga   TEXT,
            ingreso         TEXT,
            egreso          TEXT,
            nombre_pac      TEXT,
            coseguro        REAL,
            orden           TEXT,
            tipo_int        TEXT,
            tipoing         TEXT,
            tipoegr         TEXT,
            farmacol        REAL,
            alta            REAL
        );

        CREATE INDEX IF NOT EXISTS idx_pres_periodo   ON prestaciones(periodo);
        CREATE INDEX IF NOT EXISTS idx_pres_clinica   ON prestaciones(clinica);
        CREATE INDEX IF NOT EXISTS idx_pres_tipo      ON prestaciones(tipo);
        CREATE INDEX IF NOT EXISTS idx_pres_mes_prest ON prestaciones(mes_prestacion);

        CREATE TABLE IF NOT EXISTS cargas (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            periodo    TEXT NOT NULL UNIQUE,
            filas      INTEGER NOT NULL,
            usuario    TEXT NOT NULL,
            fecha      TEXT NOT NULL DEFAULT (datetime('now')),
            nombre_archivo TEXT
        );

        """)
        # Admin por defecto
        pwd = _bcrypt.hashpw(ADMIN_PASS[:72].encode(), _bcrypt.gensalt()).decode()
        c.execute("""
            INSERT OR IGNORE INTO usuarios (username, nombre, hash_pass, rol)
            VALUES (?, 'Administrador', ?, 'admin')
        """, (ADMIN_USER, pwd))

# ─────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain[:72].encode(), _bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain[:72].encode(), hashed.encode())
    except Exception:
        return False

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")

def make_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2)) -> dict:
    err = HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid: int = payload.get("uid")
        if uid is None:
            raise err
    except JWTError:
        raise err
    with db_conn() as c:
        row = c.execute(
            "SELECT id, username, nombre, rol, activo FROM usuarios WHERE id=?", (uid,)
        ).fetchone()
    if not row or not row["activo"]:
        raise err
    return dict(row)

def require_admin(user=Depends(get_current_user)):
    if user["rol"] != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Solo admins")
    return user

def require_admin_or_interno(user=Depends(get_current_user)):
    # prestador e interno pueden consultar; solo admin puede admin
    return user

def get_clinicas_usuario(uid: int) -> Optional[List[int]]:
    """None = sin restricción (admin). Lista = clínicas permitidas."""
    with db_conn() as c:
        rol = c.execute("SELECT rol FROM usuarios WHERE id=?", (uid,)).fetchone()
        if not rol or rol["rol"] in ("admin", "directorio"):
            return None
        rows = c.execute(
            "SELECT clinica_id FROM permisos WHERE usuario_id=?", (uid,)
        ).fetchall()
        return [r["clinica_id"] for r in rows]


def parse_ids(ids_str: Optional[str], allowed: Optional[List[int]] = None) -> Optional[List[int]]:
    """Parse comma-separated IDs string. Returns None if empty, filtered list otherwise."""
    if not ids_str:
        return None
    ids = [int(x) for x in ids_str.split(",") if x.strip().isdigit()]
    if not ids:
        return None
    if allowed is not None:
        ids = [i for i in ids if i in allowed]
    return ids or None

def apply_clinica_filter(where: str, params: list, clinicas_ids: Optional[str], 
                          clinica: Optional[int], user_clinicas: Optional[List[int]]) -> tuple:
    """Apply clinica filter respecting user permissions. Returns (where, params)."""
    cids = []
    if clinicas_ids:
        cids = [int(x) for x in clinicas_ids.split(",") if x.strip().isdigit()]
    if clinica:
        cids.append(clinica)
    if cids:
        if user_clinicas is not None:
            cids = [c for c in cids if c in user_clinicas]
        if cids:
            phs = ",".join(["?"]*len(cids))
            where += f" AND clinica IN ({phs})"
            params.extend(cids)
    return where, params

def apply_periodo_filter(where: str, params: list, periodos_ids: Optional[str], periodo: Optional[str]) -> tuple:
    """Apply periodo filter — accepts comma-separated periods OR single period."""
    all_periods = []
    if periodos_ids:
        all_periods = [x.strip() for x in periodos_ids.split(",") if x.strip()]
    elif periodo:
        all_periods = [periodo]
    if all_periods:
        phs = ",".join(["?"] * len(all_periods))
        where += f" AND periodo IN ({phs})"
        params.extend(all_periods)
    return where, params


def apply_mutual_filter(where: str, params: list, mutuales_ids: Optional[str], 
                        mutual: Optional[int]) -> tuple:
    """Apply mutual filter. Returns (where, params)."""
    mids = []
    if mutuales_ids:
        mids = [int(x) for x in mutuales_ids.split(",") if x.strip().isdigit()]
    if mutual:
        mids.append(mutual)
    if mids:
        phs = ",".join(["?"]*len(mids))
        where += f" AND mutual IN ({phs})"
        params.extend(mids)
    return where, params

# ─────────────────────────────────────────────────────────────
# PYDANTIC SCHEMAS
# ─────────────────────────────────────────────────────────────
class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    usuario: dict

class UsuarioCreate(BaseModel):
    username: str
    nombre: str
    password: str
    rol: str   # admin | directorio | interno | prestador

class UsuarioUpdate(BaseModel):
    nombre: Optional[str] = None
    password: Optional[str] = None
    rol: Optional[str] = None
    activo: Optional[bool] = None

class PermisoIn(BaseModel):
    clinica_id: int
    nom_clinica: str

class ChangePasswordSelf(BaseModel):
    password_actual: str
    password_nuevo: str

class ChangePasswordAdmin(BaseModel):
    password_nuevo: str

class ResumenPeriodo(BaseModel):
    periodo: str
    tipo: str
    clinica: int
    nom_clinica: str
    filas: int
    importe_total: float
    liquida_total: float
    desfase_0: int
    desfase_1: int
    desfase_2_3: int
    desfase_4plus: int
    anio_anterior: int

# ─────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────
app = FastAPI(title="CES Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En prod: restringir al dominio del frontend
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

# ─────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────
@app.post("/auth/token", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends()):
    with db_conn() as c:
        u = c.execute(
            "SELECT * FROM usuarios WHERE username=? AND activo=1", (form.username,)
        ).fetchone()
    if not u or not verify_password(form.password, u["hash_pass"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales incorrectas")
    token = make_token({"uid": u["id"], "rol": u["rol"]})
    return {
        "access_token": token,
        "usuario": {
            "id": u["id"], "username": u["username"],
            "nombre": u["nombre"], "rol": u["rol"],
        }
    }

@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    d = {k: v for k, v in user.items() if k != "hash_pass"}
    d["show_money"]   = user["rol"] in ("admin", "directorio")
    d["show_liquida"] = True  # all authenticated roles see liquida
    d["can_admin"]    = user["rol"] == "admin"
    return d

# ─────────────────────────────────────────────────────────────
# USUARIOS (admin only)
# ─────────────────────────────────────────────────────────────
@app.get("/usuarios", dependencies=[Depends(require_admin)])
def list_usuarios():
    with db_conn() as c:
        rows = c.execute("""
            SELECT u.id, u.username, u.nombre, u.rol, u.activo, u.creado,
                   GROUP_CONCAT(p.clinica_id||':'||p.nom_clinica, '|') as clinicas
            FROM usuarios u
            LEFT JOIN permisos p ON p.usuario_id = u.id
            GROUP BY u.id ORDER BY u.id
        """).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        clinicas = []
        if d["clinicas"]:
            for item in d["clinicas"].split("|"):
                parts = item.split(":", 1)
                if len(parts) == 2:
                    clinicas.append({"clinica_id": int(parts[0]), "nom_clinica": parts[1]})
        d["clinicas_list"] = clinicas
        result.append(d)
    return result

@app.post("/usuarios", dependencies=[Depends(require_admin)])
def create_usuario(body: UsuarioCreate):
    if body.rol not in ("admin", "directorio", "interno", "prestador"):
        raise HTTPException(400, "Rol inválido")
    hashed = hash_password(body.password)
    with db_conn() as c:
        try:
            c.execute(
                "INSERT INTO usuarios (username, nombre, hash_pass, rol) VALUES (?,?,?,?)",
                (body.username, body.nombre, hashed, body.rol)
            )
            uid = c.execute("SELECT last_insert_rowid()").fetchone()[0]
        except sqlite3.IntegrityError:
            raise HTTPException(400, f"El usuario '{body.username}' ya existe")
    return {"id": uid, "username": body.username, "rol": body.rol}

@app.patch("/usuarios/{uid}", dependencies=[Depends(require_admin)])
def update_usuario(uid: int, body: UsuarioUpdate):
    updates, params = [], []
    if body.nombre is not None:
        updates.append("nombre=?"); params.append(body.nombre)
    if body.password is not None:
        updates.append("hash_pass=?"); params.append(hash_password(body.password))
    if body.rol is not None:
        if body.rol not in ("admin", "directorio", "interno", "prestador"):
            raise HTTPException(400, "Rol inválido")
        updates.append("rol=?"); params.append(body.rol)
    if body.activo is not None:
        updates.append("activo=?"); params.append(int(body.activo))
    if not updates:
        raise HTTPException(400, "Nada para actualizar")
    params.append(uid)
    with db_conn() as c:
        c.execute(f"UPDATE usuarios SET {', '.join(updates)} WHERE id=?", params)
    return {"ok": True}

@app.delete("/usuarios/{uid}", dependencies=[Depends(require_admin)])
def delete_usuario(uid: int):
    with db_conn() as c:
        c.execute("DELETE FROM usuarios WHERE id=? AND rol != 'admin'", (uid,))
    return {"ok": True}

# ─────────────────────────────────────────────────────────────
# PERMISOS (admin only)
# ─────────────────────────────────────────────────────────────
@app.get("/usuarios/{uid}/permisos", dependencies=[Depends(require_admin)])
def get_permisos(uid: int):
    with db_conn() as c:
        rows = c.execute(
            "SELECT clinica_id, nom_clinica FROM permisos WHERE usuario_id=? ORDER BY clinica_id",
            (uid,)
        ).fetchall()
    return [dict(r) for r in rows]

@app.post("/usuarios/{uid}/permisos", dependencies=[Depends(require_admin)])
def add_permiso(uid: int, body: PermisoIn):
    with db_conn() as c:
        try:
            c.execute(
                "INSERT INTO permisos (usuario_id, clinica_id, nom_clinica) VALUES (?,?,?)",
                (uid, body.clinica_id, body.nom_clinica)
            )
        except sqlite3.IntegrityError:
            raise HTTPException(400, "Permiso ya existe")
    return {"ok": True}

@app.delete("/usuarios/{uid}/permisos/{clinica_id}", dependencies=[Depends(require_admin)])
def remove_permiso(uid: int, clinica_id: int):
    with db_conn() as c:
        c.execute(
            "DELETE FROM permisos WHERE usuario_id=? AND clinica_id=?", (uid, clinica_id)
        )
    return {"ok": True}

@app.put("/usuarios/{uid}/permisos", dependencies=[Depends(require_admin)])
def set_permisos(uid: int, body: List[PermisoIn]):
    """Reemplaza todos los permisos del usuario de una vez."""
    with db_conn() as c:
        c.execute("DELETE FROM permisos WHERE usuario_id=?", (uid,))
        for p in body:
            c.execute(
                "INSERT INTO permisos (usuario_id, clinica_id, nom_clinica) VALUES (?,?,?)",
                (uid, p.clinica_id, p.nom_clinica)
            )
    return {"ok": True, "total": len(body)}

# ─────────────────────────────────────────────────────────────
# CAMBIO DE CONTRASEÑA
# ─────────────────────────────────────────────────────────────
@app.post("/auth/change-password")
def change_my_password(body: ChangePasswordSelf, user=Depends(get_current_user)):
    """Cualquier usuario (no admin) puede cambiar su propia contraseña confirmando la actual."""
    if user["rol"] == "admin":
        raise HTTPException(400, "El admin cambia su contraseña desde Railway (variable ADMIN_PASS)")
    if len(body.password_nuevo.strip()) < 6:
        raise HTTPException(400, "La nueva contraseña debe tener al menos 6 caracteres")
    with db_conn() as c:
        row = c.execute("SELECT hash_pass FROM usuarios WHERE id=?", (user["id"],)).fetchone()
    if not row or not verify_password(body.password_actual, row["hash_pass"]):
        raise HTTPException(400, "Contraseña actual incorrecta")
    new_hash = hash_password(body.password_nuevo[:72])
    with db_conn() as c:
        c.execute("UPDATE usuarios SET hash_pass=? WHERE id=?", (new_hash, user["id"]))
    return {"ok": True, "mensaje": "Contraseña actualizada correctamente"}

@app.post("/usuarios/{uid}/change-password", dependencies=[Depends(require_admin)])
def admin_change_password(uid: int, body: ChangePasswordAdmin):
    """Admin puede cambiar la contraseña de cualquier usuario (no admin)."""
    with db_conn() as c:
        row = c.execute("SELECT rol FROM usuarios WHERE id=?", (uid,)).fetchone()
    if not row:
        raise HTTPException(404, "Usuario no encontrado")
    if row["rol"] == "admin":
        raise HTTPException(400, "No se puede cambiar la contraseña del admin desde aquí")
    if len(body.password_nuevo.strip()) < 6:
        raise HTTPException(400, "La nueva contraseña debe tener al menos 6 caracteres")
    new_hash = hash_password(body.password_nuevo[:72])
    with db_conn() as c:
        c.execute("UPDATE usuarios SET hash_pass=? WHERE id=?", (new_hash, uid))
    return {"ok": True, "mensaje": "Contraseña actualizada por admin"}

# ─────────────────────────────────────────────────────────────
# CARGA DE EXCEL (admin only)
# ─────────────────────────────────────────────────────────────
COL_MAP = {
    "TIPO": "tipo", "PERIODO": "periodo",
    "FECHA_REF": "fecha_ref", "MES_PRESTACION": "mes_prestacion",
    "DESFASE_MESES": "desfase_meses", "ANIO_ANTERIOR": "anio_anterior",
    "LOTE": "lote", "CLINICA": "clinica", "NomClinica": "nom_clinica",
    "MUTUAL": "mutual", "NomMutual": "nom_mutual",
    "PRACTICA": "practica", "NomPractica": "nom_practica",
    "SUBCODIGO": "subcodigo", "ITEM": "item",
    "FECHA": "fecha", "CANTIDAD": "cantidad",
    "CUENTA": "cuenta", "NomCuenta": "nom_cuenta",
    "IMPORTE": "importe", "LIQUIDA": "liquida", "IMP2": "imp2",
    "EFECTOR": "efector", "NomEfector": "nom_efector",
    "MATRICULA": "matricula", "Mat_Efector": "mat_efector",
    "AFILIADO": "afiliado", "DOCUMENTO": "documento", "NOM_AFI": "nom_afi",
    "SEXO": "sexo", "EDAD": "edad", "DIAG": "diag",
    "AUTORIZA": "autoriza", "ARANCELA": "arancela", "PASA": "pasa",
    "REFACTURA": "refactura", "FORMULA": "formula", "SUCFORMULA": "sucformula",
    "FECHAPRES": "fechapres", "DERIVA": "deriva", "USUARIO": "usuario_carga",
    "INGRESO": "ingreso", "EGRESO": "egreso", "NOMBRE": "nombre_pac",
    "COSEGURO": "coseguro", "ORDEN": "orden",
    "TIPO_INT": "tipo_int", "TIPOING": "tipoing", "TIPOEGR": "tipoegr",
    "FARMACOL": "farmacol", "ALTA": "alta",
}

@app.post("/carga/upload")
def upload_excel(
    file: UploadFile = File(...),
    reemplazar: bool = Query(False, description="Si True, borra el período antes de insertar"),
    user=Depends(require_admin)
):
    if not file.filename.endswith((".xlsx", ".xls")):
        raise HTTPException(400, "Solo archivos .xlsx o .xls")
    content = file.file.read()
    try:
        xl = pd.ExcelFile(io.BytesIO(content))
        # Preferir hoja "Consolidado", si no existe usar la primera hoja
        sheet = "Consolidado" if "Consolidado" in xl.sheet_names else xl.sheet_names[0]
        df = pd.read_excel(io.BytesIO(content), sheet_name=sheet, dtype=str)
    except Exception as e:
        raise HTTPException(400, f"No se pudo leer el archivo: {e}")

    # Validar columnas mínimas
    missing = REQUIRED_COLS - set(df.columns)
    if missing:
        raise HTTPException(400, f"Columnas faltantes: {', '.join(sorted(missing))}")

    df = df.where(pd.notna(df), None)

    # Detectar períodos — los XLS históricos pueden tener varios
    periodos_en_archivo = sorted(set(
        str(p).strip() for p in df["PERIODO"].dropna().unique()
    ))
    if not periodos_en_archivo:
        raise HTTPException(400, "La columna PERIODO está vacía")

    # Para el registro de carga usamos el primero (o el único)
    periodo_registro = periodos_en_archivo[0] if len(periodos_en_archivo) == 1 \
                       else f"{periodos_en_archivo[0]}..{periodos_en_archivo[-1]}"

    with db_conn() as c:
        # Verificar períodos que ya existen
        conflictos = []
        for p in periodos_en_archivo:
            row = c.execute("SELECT filas FROM cargas WHERE periodo=?", (p,)).fetchone()
            if row:
                conflictos.append(f"{p} ({row['filas']} filas)")
        if conflictos and not reemplazar:
            raise HTTPException(
                409,
                f"Períodos ya cargados: {', '.join(conflictos)}. "
                f"Usá reemplazar=true para sobreescribir."
            )
        if reemplazar:
            for p in periodos_en_archivo:
                c.execute("DELETE FROM prestaciones WHERE periodo=?", (p,))
                c.execute("DELETE FROM cargas WHERE periodo=?", (p,))

        # Alias para el bloque de inserción
        periodo = periodo_registro

        # Insertar filas
        db_cols = list(COL_MAP.values())
        placeholders = ",".join(["?"] * len(db_cols))
        insert_sql = f"INSERT INTO prestaciones ({','.join(db_cols)}) VALUES ({placeholders})"

        rows_to_insert = []
        for _, row in df.iterrows():
            vals = []
            for excel_col, db_col in COL_MAP.items():
                val = row.get(excel_col)
                if val is not None:
                    try:
                        if db_col in ("importe", "liquida", "imp2", "cantidad", "coseguro", "farmacol", "alta"):
                            val = float(val) if val != "" else None
                        elif db_col in ("clinica", "mutual", "practica", "item", "edad", "desfase_meses"):
                            val = int(float(val)) if val != "" else None
                    except (ValueError, TypeError):
                        val = None
                vals.append(val)
            rows_to_insert.append(vals)

        c.executemany(insert_sql, rows_to_insert)

        # Registrar una entrada en cargas por cada período detectado
        conteo_periodos = df.groupby("PERIODO").size().to_dict()
        for p, n in conteo_periodos.items():
            p = str(p).strip()
            c.execute(
                "INSERT OR REPLACE INTO cargas (periodo, filas, usuario, nombre_archivo) VALUES (?,?,?,?)",
                (p, int(n), user["username"], file.filename)
            )

    return {
        "ok": True,
        "periodos": periodos_en_archivo,
        "hoja_leida": sheet,
        "filas_insertadas": len(rows_to_insert),
        "detalle_por_periodo": {str(k).strip(): int(v) for k, v in df.groupby("PERIODO").size().items()},
        "reemplazado": reemplazar,
    }

@app.get("/carga/historial", dependencies=[Depends(require_admin)])
def historial_cargas():
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM cargas ORDER BY periodo DESC"
        ).fetchall()
    return [dict(r) for r in rows]

@app.delete("/carga/{periodo}", dependencies=[Depends(require_admin)])
def delete_periodo(periodo: str):
    with db_conn() as c:
        c.execute("DELETE FROM prestaciones WHERE periodo=?", (periodo,))
        c.execute("DELETE FROM cargas WHERE periodo=?", (periodo,))
    return {"ok": True, "periodo": periodo}

# ─────────────────────────────────────────────────────────────
# CONSULTAS
# ─────────────────────────────────────────────────────────────
def clinica_filter(clinicas: Optional[List[int]]) -> tuple:
    """Devuelve (sql_fragment, params) para filtrar por clínicas."""
    if clinicas is None:
        return ("", [])
    if not clinicas:
        return (" AND 1=0", [])  # sin permisos = nada
    placeholders = ",".join(["?"] * len(clinicas))
    return (f" AND clinica IN ({placeholders})", clinicas)

@app.get("/periodos")
def get_periodos(user=Depends(get_current_user)):
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    with db_conn() as c:
        rows = c.execute(
            f"SELECT DISTINCT periodo FROM prestaciones WHERE 1=1{cf} ORDER BY periodo DESC",
            cp
        ).fetchall()
    return [r["periodo"] for r in rows]

@app.get("/clinicas")
def get_clinicas(user=Depends(get_current_user)):
    """Clínicas visibles para el usuario."""
    clinicas = get_clinicas_usuario(user["id"])
    if clinicas is None:
        with db_conn() as c:
            rows = c.execute(
                "SELECT DISTINCT clinica, nom_clinica FROM prestaciones ORDER BY nom_clinica"
            ).fetchall()
    else:
        with db_conn() as c:
            phs = ",".join(["?"] * len(clinicas)) if clinicas else "NULL"
            rows = c.execute(
                f"SELECT DISTINCT clinica, nom_clinica FROM prestaciones WHERE clinica IN ({phs}) ORDER BY nom_clinica",
                clinicas
            ).fetchall()
    return [{"clinica_id": r["clinica"], "nom_clinica": r["nom_clinica"]} for r in rows]

@app.get("/mutuales")
def get_mutuales(
    periodo: Optional[str] = None,
    periodos_ids: Optional[str] = Query(None, description="Períodos separados por coma"),
    clinica: Optional[int] = None,
    user=Depends(get_current_user)
):
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    where, params = apply_periodo_filter(where, params, periodos_ids, periodo)
    if clinica:
        if clinicas is not None and clinica not in clinicas:
            return []
        where += " AND clinica=?"; params.append(clinica)
    with db_conn() as c:
        rows = c.execute(
            f"SELECT DISTINCT mutual, nom_mutual FROM prestaciones WHERE {where} ORDER BY nom_mutual",
            params
        ).fetchall()
    return [{"mutual_id": r["mutual"], "nom_mutual": r["nom_mutual"]} for r in rows]

@app.get("/resumen")
def get_resumen(
    periodo: Optional[str] = None,
    periodos_ids: Optional[str] = Query(None, description="Períodos separados por coma"),
    agrupar: Optional[str] = Query(None, description="mutual = agrupar por financiador"),
    clinica: Optional[int] = None,
    clinicas_ids: Optional[str] = Query(None),
    mutual: Optional[int] = None,
    mutuales_ids: Optional[str] = Query(None),
    tipo: Optional[str] = None,
    mes_prestacion: Optional[str] = None,
    user=Depends(get_current_user)
):
    """KPIs y resumen agrupado por período + clínica + tipo."""
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    where, params = apply_periodo_filter(where, params, periodos_ids, periodo)
    if tipo:           where += " AND tipo=?";            params.append(tipo.upper())
    if mes_prestacion: where += " AND mes_prestacion=?";  params.append(mes_prestacion)
    where, params = apply_clinica_filter(where, params, clinicas_ids, clinica, clinicas)
    where, params = apply_mutual_filter(where, params, mutuales_ids, mutual)

    show_money = user["rol"] in ("admin", "directorio")
    # Mutual grouping mode
    if agrupar == "mutual":
        with db_conn() as c:
            rows = c.execute(f"""
                SELECT periodo, tipo, mutual, nom_mutual,
                       COUNT(*) as filas,
                       COALESCE(SUM(importe),0) as importe_total,
                       COALESCE(SUM(liquida),0) as liquida_total
                FROM prestaciones WHERE {where}
                GROUP BY periodo, tipo, mutual, nom_mutual
                ORDER BY periodo DESC, liquida_total DESC
            """, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if not show_money: d["importe_total"] = None
            result.append(d)
        return result
    with db_conn() as c:
        rows = c.execute(f"""
            SELECT
                periodo, tipo, clinica, nom_clinica,
                COUNT(*) as filas,
                COALESCE(SUM(importe), 0) as importe_total,
                COALESCE(SUM(liquida), 0) as liquida_total,
                SUM(CASE WHEN desfase_meses = 0 THEN 1 ELSE 0 END) as desfase_0,
                SUM(CASE WHEN desfase_meses = 1 THEN 1 ELSE 0 END) as desfase_1,
                SUM(CASE WHEN desfase_meses BETWEEN 2 AND 3 THEN 1 ELSE 0 END) as desfase_2_3,
                SUM(CASE WHEN desfase_meses >= 4 THEN 1 ELSE 0 END) as desfase_4plus,
                SUM(CASE WHEN anio_anterior = 'SÍ' THEN 1 ELSE 0 END) as anio_anterior
            FROM prestaciones WHERE {where}
            GROUP BY periodo, tipo, clinica, nom_clinica
            ORDER BY periodo DESC, liquida_total DESC, tipo
        """, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if not show_money:
            d["importe_total"] = None
        result.append(d)
    return result


@app.get("/resumen/detalle")
def get_resumen_detalle(
    periodo: Optional[str] = None,
    periodos_ids: Optional[str] = Query(None, description="Períodos separados por coma"),
    clinicas_ids: Optional[str] = Query(None),
    mutuales_ids: Optional[str] = Query(None),
    tipo: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Detalle drill-down: dado clínica devuelve financiadores; dado financiador devuelve clínicas."""
    clinicas_usuario = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas_usuario)
    params = []; where = f"1=1{cf}"; params.extend(cp)
    where, params = apply_periodo_filter(where, params, periodos_ids, periodo)
    if tipo:     where += " AND tipo=?";     params.append(tipo.upper())
    where, params = apply_clinica_filter(where, params, clinicas_ids, None, clinicas_usuario)
    where, params = apply_mutual_filter(where, params, mutuales_ids, None)

    show_money = user["rol"] in ("admin", "directorio")

    # If filtering by clinica → return financiadores breakdown
    # If filtering by mutual → return clinicas breakdown
    if clinicas_ids and not mutuales_ids:
        with db_conn() as c:
            rows = c.execute(f"""
                SELECT periodo, tipo, mutual, nom_mutual,
                       COUNT(*) as filas,
                       COALESCE(SUM(importe),0) as importe_total,
                       COALESCE(SUM(liquida),0) as liquida_total
                FROM prestaciones WHERE {where}
                GROUP BY periodo, tipo, mutual, nom_mutual
                ORDER BY liquida_total DESC
            """, params).fetchall()
    else:
        with db_conn() as c:
            rows = c.execute(f"""
                SELECT periodo, tipo, clinica, nom_clinica,
                       COUNT(*) as filas,
                       COALESCE(SUM(importe),0) as importe_total,
                       COALESCE(SUM(liquida),0) as liquida_total
                FROM prestaciones WHERE {where}
                GROUP BY periodo, tipo, clinica, nom_clinica
                ORDER BY liquida_total DESC
            """, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if not show_money: d["importe_total"] = None
        result.append(d)
    return result

@app.get("/kpis")
def get_kpis(
    periodo: Optional[str] = None,
    periodos_ids: Optional[str] = Query(None, description="Períodos separados por coma"),
    clinica: Optional[int] = None,
    clinicas_ids: Optional[str] = Query(None),
    mutual: Optional[int] = None,
    mutuales_ids: Optional[str] = Query(None),
    tipo: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Totales para la cabecera del dashboard."""
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    where, params = apply_periodo_filter(where, params, periodos_ids, periodo)
    if tipo:     where += " AND tipo=?";     params.append(tipo.upper())
    where, params = apply_clinica_filter(where, params, clinicas_ids, clinica, clinicas)
    where, params = apply_mutual_filter(where, params, mutuales_ids, mutual)

    with db_conn() as c:
        r = c.execute(f"""
            SELECT
                COUNT(*) as total_filas,
                COUNT(DISTINCT lote) as total_lotes,
                COUNT(DISTINCT clinica) as total_clinicas,
                COUNT(DISTINCT mutual) as total_mutuales,
                COUNT(DISTINCT mes_prestacion) as meses_distintos,
                COALESCE(SUM(importe), 0) as importe_total,
                COALESCE(SUM(liquida), 0) as liquida_total,
                SUM(CASE WHEN tipo='AMB' THEN 1 ELSE 0 END) as filas_amb,
                SUM(CASE WHEN tipo='INT' THEN 1 ELSE 0 END) as filas_int,
                COALESCE(SUM(CASE WHEN tipo='AMB' THEN importe ELSE 0 END), 0) as importe_amb,
                COALESCE(SUM(CASE WHEN tipo='INT' THEN importe ELSE 0 END), 0) as importe_int,
                COALESCE(SUM(CASE WHEN tipo='AMB' THEN liquida ELSE 0 END), 0) as liquida_amb,
                COALESCE(SUM(CASE WHEN tipo='INT' THEN liquida ELSE 0 END), 0) as liquida_int,
                SUM(CASE WHEN anio_anterior='SÍ' THEN 1 ELSE 0 END) as anio_anterior
            FROM prestaciones WHERE {where}
        """, params).fetchone()
    d = dict(r)
    if user["rol"] not in ("admin", "directorio"):
        d["importe_total"] = None
        d["importe_amb"] = None
        d["importe_int"] = None
        # liquida visible for all roles
    return d

@app.get("/desfase")
def get_desfase(
    periodo: Optional[str] = None,
    periodos_ids: Optional[str] = Query(None, description="Períodos separados por coma"),
    clinica: Optional[int] = None,
    clinicas_ids: Optional[str] = Query(None),
    mutual: Optional[int] = None,
    mutuales_ids: Optional[str] = Query(None),
    tipo: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Distribución de desfase para el gráfico."""
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    where, params = apply_periodo_filter(where, params, periodos_ids, periodo)
    if tipo:    where += " AND tipo=?";    params.append(tipo.upper())
    where, params = apply_clinica_filter(where, params, clinicas_ids, clinica, clinicas)
    where, params = apply_mutual_filter(where, params, mutuales_ids, mutual)

    with db_conn() as c:
        rows = c.execute(f"""
            SELECT
                mes_prestacion,
                COUNT(*) as filas,
                COALESCE(SUM(importe), 0) as importe
            FROM prestaciones
            WHERE {where} AND mes_prestacion IS NOT NULL AND mes_prestacion != ''
            GROUP BY mes_prestacion
            ORDER BY mes_prestacion
        """, params).fetchall()
    return [dict(r) for r in rows]

@app.get("/detalle")
def get_detalle(
    periodo: Optional[str] = None,
    periodos_ids: Optional[str] = Query(None, description="Períodos separados por coma"),
    clinica: Optional[int] = None,
    clinicas_ids: Optional[str] = Query(None),
    mutual: Optional[int] = None,
    mutuales_ids: Optional[str] = Query(None),
    tipo: Optional[str] = None,
    mes_prestacion: Optional[str] = None,
    desfase_min: Optional[int] = None,
    desfase_max: Optional[int] = None,
    solo_anio_anterior: bool = False,
    limit: int = Query(500, le=2000),
    offset: int = 0,
    user=Depends(get_current_user)
):
    """Tabla detalle paginada."""
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    where, params = apply_periodo_filter(where, params, periodos_ids, periodo)
    if tipo:            where += " AND tipo=?";              params.append(tipo.upper())
    where, params = apply_clinica_filter(where, params, clinicas_ids, clinica, clinicas)
    where, params = apply_mutual_filter(where, params, mutuales_ids, mutual)
    if mes_prestacion:  where += " AND mes_prestacion=?";    params.append(mes_prestacion)
    if desfase_min is not None: where += " AND desfase_meses>=?"; params.append(desfase_min)
    if desfase_max is not None: where += " AND desfase_meses<=?"; params.append(desfase_max)
    if solo_anio_anterior:      where += " AND anio_anterior='SÍ'"

    with db_conn() as c:
        total = c.execute(
            f"SELECT COUNT(*) FROM prestaciones WHERE {where}", params
        ).fetchone()[0]
        # importe solo para admin y directorio; liquida visible para todos
        show_money = user["rol"] in ("admin", "directorio")
        money_cols = "importe," if show_money else "NULL as importe,"
        money_cols += " liquida,"  # all roles see liquida
        rows = c.execute(
            f"""SELECT id, periodo, tipo, fecha_ref, mes_prestacion, desfase_meses,
                       anio_anterior, lote, clinica, nom_clinica, mutual, nom_mutual,
                       practica, nom_practica, item, fecha, cantidad,
                       cuenta, nom_cuenta, {money_cols}
                       afiliado, nom_afi, documento, diag, usuario_carga,
                       ingreso, egreso, nombre_pac, coseguro
                FROM prestaciones WHERE {where}
                ORDER BY periodo DESC, nom_clinica, lote, item
                LIMIT ? OFFSET ?""",
            params + [limit, offset]
        ).fetchall()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "data": [dict(r) for r in rows]
    }

# ─────────────────────────────────────────────────────────────
# DESCARGA EXCEL
# ─────────────────────────────────────────────────────────────
@app.get("/descarga/excel")
def download_excel(
    periodo: Optional[str] = None,
    periodos_ids: Optional[str] = Query(None, description="Períodos separados por coma"),
    clinica: Optional[int] = None,
    clinicas_ids: Optional[str] = Query(None),
    mutual: Optional[int] = None,
    mutuales_ids: Optional[str] = Query(None),
    tipo: Optional[str] = None,
    mes_prestacion: Optional[str] = None,
    desfase_min: Optional[int] = None,
    solo_anio_anterior: bool = False,
    user=Depends(get_current_user)
):
    """Descarga Excel filtrado por los permisos del usuario."""
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    where, params = apply_periodo_filter(where, params, periodos_ids, periodo)
    if tipo:            where += " AND tipo=?";             params.append(tipo.upper())
    where, params = apply_clinica_filter(where, params, clinicas_ids, clinica, clinicas)
    where, params = apply_mutual_filter(where, params, mutuales_ids, mutual)
    if mes_prestacion:  where += " AND mes_prestacion=?";   params.append(mes_prestacion)
    if desfase_min is not None: where += " AND desfase_meses>=?"; params.append(desfase_min)
    if solo_anio_anterior:      where += " AND anio_anterior='SÍ'"

    with db_conn() as c:
        rows = c.execute(
            f"SELECT * FROM prestaciones WHERE {where} ORDER BY periodo DESC, nom_clinica, lote, item",
            params
        ).fetchall()

    if not rows:
        raise HTTPException(404, "Sin datos para los filtros seleccionados")

    df = pd.DataFrame([dict(r) for r in rows])
    # Renombrar a nombres legibles
    df.rename(columns={v: k for k, v in COL_MAP.items()}, inplace=True)
    # Ocultar IMPORTE para roles sin permiso (todos ven LIQUIDA)
    if user["rol"] not in ("admin", "directorio"):
        cols_to_drop = [c for c in ["IMPORTE", "IMP2"] if c in df.columns]
        if cols_to_drop:
            df.drop(columns=cols_to_drop, inplace=True)

    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name="Detalle", index=False)
        wb = writer.book
        ws = writer.sheets["Detalle"]
        header_fmt = wb.add_format({"bold": True, "bg_color": "#1B3A6B", "font_color": "#FFFFFF"})
        for col_num, col_name in enumerate(df.columns):
            ws.write(0, col_num, col_name, header_fmt)
            ws.set_column(col_num, col_num, max(len(str(col_name)) + 2, 12))

    buf.seek(0)
    filename = f"CES_{user['username']}_{periodo or 'todo'}.xlsx"
    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ─────────────────────────────────────────────────────────────
# ANÁLISIS AVANZADOS
# ─────────────────────────────────────────────────────────────
@app.get("/analisis/practicas")
def get_analisis_practicas(
    periodo: Optional[str] = None,
    periodos_ids: Optional[str] = Query(None, description="Períodos separados por coma"),
    clinica: Optional[int] = Query(None),
    clinicas_ids: Optional[str] = Query(None, description="IDs separados por coma"),
    mutual: Optional[int] = Query(None),
    mutuales_ids: Optional[str] = Query(None, description="IDs separados por coma"),
    practicas_ids: Optional[str] = Query(None, description="Códigos de práctica separados por coma"),
    tipo: Optional[str] = None,
    top: int = Query(20, le=100),
    user=Depends(get_current_user)
):
    """Prácticas más frecuentes con desglose por prestador y financiador."""
    clinicas_usuario = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas_usuario)
    params = []; where = f"1=1{cf}"; params.extend(cp)
    where, params = apply_periodo_filter(where, params, periodos_ids, periodo)
    if tipo:       where += " AND tipo=?";      params.append(tipo.upper())
    where, params = apply_clinica_filter(where, params, clinicas_ids, clinica, clinicas_usuario)
    where, params = apply_mutual_filter(where, params, mutuales_ids, mutual)
    # Filter by specific practices
    if practicas_ids:
        pids = [x.strip() for x in practicas_ids.split(",") if x.strip()]
        if pids:
            phs = ",".join(["?"] * len(pids))
            where += f" AND CAST(practica AS TEXT) IN ({phs})"
            params.extend(pids)

    show_money = user["rol"] in ("admin", "directorio")
    money_col = "COALESCE(SUM(importe), 0) as importe_total," if show_money else "NULL as importe_total,"

    with db_conn() as c:
        rows = c.execute(f"""
            SELECT practica, nom_practica, nom_clinica, nom_mutual,
                   COUNT(*) as cantidad,
                   COALESCE(SUM(liquida), 0) as liquida_total,
                   {money_col}
                   CASE WHEN COUNT(*)>0 THEN COALESCE(SUM(liquida),0)/COUNT(*) ELSE 0 END as prom_liquida
            FROM prestaciones WHERE {where}
              AND practica IS NOT NULL AND practica != ''
            GROUP BY practica, nom_practica, nom_clinica, nom_mutual
            ORDER BY liquida_total DESC
            LIMIT ?
        """, params + [top]).fetchall()
    return [dict(r) for r in rows]

@app.get("/analisis/evolucion")
def get_evolucion(
    clinica: Optional[int] = Query(None),
    clinicas_ids: Optional[str] = Query(None),
    mutual: Optional[int] = Query(None),
    mutuales_ids: Optional[str] = Query(None),
    tipo: Optional[str] = None,
    agrupar_por: str = Query("prestador", description="prestador | financiador | prestador_financiador"),
    user=Depends(get_current_user)
):
    """Evolución de facturación por período, agrupada por prestador/financiador."""
    clinicas_usuario = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas_usuario)
    params = []; where = f"1=1{cf}"; params.extend(cp)
    if tipo: where += " AND tipo=?"; params.append(tipo.upper())

    where, params = apply_clinica_filter(where, params, clinicas_ids, clinica, clinicas_usuario)
    where, params = apply_mutual_filter(where, params, mutuales_ids, mutual)

    if agrupar_por == "prestador":
        group_cols = "periodo, nom_clinica"
        select_cols = "periodo, nom_clinica as etiqueta, '' as etiqueta2"
    elif agrupar_por == "financiador":
        group_cols = "periodo, nom_mutual"
        select_cols = "periodo, nom_mutual as etiqueta, '' as etiqueta2"
    else:  # prestador_financiador
        group_cols = "periodo, nom_clinica, nom_mutual"
        select_cols = "periodo, nom_clinica as etiqueta, nom_mutual as etiqueta2"

    with db_conn() as c:
        rows = c.execute(f"""
            SELECT {select_cols},
                   COUNT(*) as cantidad,
                   COALESCE(SUM(importe), 0) as importe_total
            FROM prestaciones WHERE {where}
            GROUP BY {group_cols}
            ORDER BY periodo, etiqueta
        """, params).fetchall()
    return [dict(r) for r in rows]

# ─────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────
@app.get("/version")
def version():
    """Endpoint para verificar qué versión está corriendo."""
    return {"version": "2026-04-17-periodos-ids", "analisis_practicas": "uses apply_clinica_filter + periodos_ids"}



@app.get("/admin/check-db", dependencies=[Depends(require_admin)])
def check_db():
    """Diagnóstico: lista tablas y columnas de la BD."""
    with db_conn() as c:
        tables = c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        result = {}
        for t in tables:
            tname = t["name"]
            cols = c.execute(f"PRAGMA table_info({tname})").fetchall()
            result[tname] = [col["name"] for col in cols]
    return {"db": DB_PATH, "tables": result}

@app.post("/admin/fix-db", dependencies=[Depends(require_admin)])
def fix_db():
    """Recrea permisos con FK correcta a usuarios, preservando datos."""
    with db_conn() as c:
        # Leer permisos existentes para preservarlos
        try:
            existing = c.execute("SELECT usuario_id, clinica_id, nom_clinica FROM permisos").fetchall()
        except Exception:
            existing = []
        # Borrar tabla permisos con FK rota
        c.execute("DROP TABLE IF EXISTS permisos")
        # Recrear con FK correcta
        c.execute("""
            CREATE TABLE permisos (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                clinica_id INTEGER NOT NULL,
                nom_clinica TEXT NOT NULL,
                UNIQUE(usuario_id, clinica_id)
            )
        """)
        # Restaurar datos
        for row in existing:
            try:
                c.execute(
                    "INSERT OR IGNORE INTO permisos (usuario_id, clinica_id, nom_clinica) VALUES (?,?,?)",
                    (row["usuario_id"], row["clinica_id"], row["nom_clinica"])
                )
            except Exception:
                pass
    return {"ok": True, "msg": "Tabla permisos recreada con FK correcta", "filas_restauradas": len(existing)}

@app.get("/health")
def health():
    with db_conn() as c:
        periodos = c.execute(
            "SELECT COUNT(*) as n, MAX(periodo) as ultimo FROM cargas"
        ).fetchone()
    return {
        "status": "ok",
        "periodos_cargados": periodos["n"],
        "ultimo_periodo": periodos["ultimo"],
        "db": DB_PATH,
    }
