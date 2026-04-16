"""
GEA Dashboard — Backend
FastAPI + SQLite + JWT
"""
import os, io, sqlite3, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from contextlib import contextmanager

import pandas as pd
from fastapi import (
    FastAPI, Depends, HTTPException, UploadFile, File,
    status, Query, Response
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM   = "HS256"
TOKEN_HOURS = int(os.getenv("TOKEN_HOURS", "12"))
DB_PATH     = os.getenv("DB_PATH", "/data/gea.db")   # Railway volume
ADMIN_USER  = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS  = os.getenv("ADMIN_PASS", "gea2026")

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
            rol       TEXT NOT NULL CHECK(rol IN ('admin','interno','prestador')),
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
        pwd = CryptContext(schemes=["bcrypt"]).hash(ADMIN_PASS)
        c.execute("""
            INSERT OR IGNORE INTO usuarios (username, nombre, hash_pass, rol)
            VALUES (?, 'Administrador', ?, 'admin')
        """, (ADMIN_USER, pwd))

# ─────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2     = OAuth2PasswordBearer(tokenUrl="/auth/token")

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

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
    if user["rol"] == "prestador":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Acceso restringido")
    return user

def get_clinicas_usuario(uid: int) -> Optional[List[int]]:
    """None = sin restricción (admin). Lista = clínicas permitidas."""
    with db_conn() as c:
        rol = c.execute("SELECT rol FROM usuarios WHERE id=?", (uid,)).fetchone()
        if not rol or rol["rol"] == "admin":
            return None
        rows = c.execute(
            "SELECT clinica_id FROM permisos WHERE usuario_id=?", (uid,)
        ).fetchall()
        return [r["clinica_id"] for r in rows]

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
    rol: str   # admin | interno | prestador

class UsuarioUpdate(BaseModel):
    nombre: Optional[str] = None
    password: Optional[str] = None
    rol: Optional[str] = None
    activo: Optional[bool] = None

class PermisoIn(BaseModel):
    clinica_id: int
    nom_clinica: str

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
app = FastAPI(title="GEA Dashboard API", version="1.0.0")

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
    return user

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
    if body.rol not in ("admin", "interno", "prestador"):
        raise HTTPException(400, "Rol inválido")
    hashed = pwd_context.hash(body.password)
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
        updates.append("hash_pass=?"); params.append(pwd_context.hash(body.password))
    if body.rol is not None:
        if body.rol not in ("admin", "interno", "prestador"):
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
    clinica: Optional[int] = None,
    user=Depends(get_current_user)
):
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    if periodo:
        where += " AND periodo=?"; params.append(periodo)
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
    clinica: Optional[int] = None,
    mutual: Optional[int] = None,
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
    if periodo:        where += " AND periodo=?";         params.append(periodo)
    if clinica:        where += " AND clinica=?";         params.append(clinica)
    if mutual:         where += " AND mutual=?";          params.append(mutual)
    if tipo:           where += " AND tipo=?";            params.append(tipo.upper())
    if mes_prestacion: where += " AND mes_prestacion=?";  params.append(mes_prestacion)

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
            ORDER BY periodo DESC, nom_clinica, tipo
        """, params).fetchall()
    return [dict(r) for r in rows]

@app.get("/kpis")
def get_kpis(
    periodo: Optional[str] = None,
    clinica: Optional[int] = None,
    mutual: Optional[int] = None,
    tipo: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Totales para la cabecera del dashboard."""
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    if periodo:  where += " AND periodo=?";  params.append(periodo)
    if clinica:  where += " AND clinica=?";  params.append(clinica)
    if mutual:   where += " AND mutual=?";   params.append(mutual)
    if tipo:     where += " AND tipo=?";     params.append(tipo.upper())

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
                SUM(CASE WHEN anio_anterior='SÍ' THEN 1 ELSE 0 END) as anio_anterior
            FROM prestaciones WHERE {where}
        """, params).fetchone()
    return dict(r)

@app.get("/desfase")
def get_desfase(
    periodo: Optional[str] = None,
    clinica: Optional[int] = None,
    tipo: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Distribución de desfase para el gráfico."""
    clinicas = get_clinicas_usuario(user["id"])
    cf, cp = clinica_filter(clinicas)
    params = []
    where = f"1=1{cf}"
    params.extend(cp)
    if periodo: where += " AND periodo=?"; params.append(periodo)
    if clinica: where += " AND clinica=?"; params.append(clinica)
    if tipo:    where += " AND tipo=?";    params.append(tipo.upper())

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
    clinica: Optional[int] = None,
    mutual: Optional[int] = None,
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
    if periodo:         where += " AND periodo=?";           params.append(periodo)
    if clinica:         where += " AND clinica=?";           params.append(clinica)
    if mutual:          where += " AND mutual=?";            params.append(mutual)
    if tipo:            where += " AND tipo=?";              params.append(tipo.upper())
    if mes_prestacion:  where += " AND mes_prestacion=?";    params.append(mes_prestacion)
    if desfase_min is not None: where += " AND desfase_meses>=?"; params.append(desfase_min)
    if desfase_max is not None: where += " AND desfase_meses<=?"; params.append(desfase_max)
    if solo_anio_anterior:      where += " AND anio_anterior='SÍ'"

    with db_conn() as c:
        total = c.execute(
            f"SELECT COUNT(*) FROM prestaciones WHERE {where}", params
        ).fetchone()[0]
        rows = c.execute(
            f"""SELECT id, periodo, tipo, fecha_ref, mes_prestacion, desfase_meses,
                       anio_anterior, lote, clinica, nom_clinica, mutual, nom_mutual,
                       practica, nom_practica, item, fecha, cantidad,
                       cuenta, nom_cuenta, importe, liquida,
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
    clinica: Optional[int] = None,
    mutual: Optional[int] = None,
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
    if periodo:         where += " AND periodo=?";          params.append(periodo)
    if clinica:         where += " AND clinica=?";          params.append(clinica)
    if mutual:          where += " AND mutual=?";           params.append(mutual)
    if tipo:            where += " AND tipo=?";             params.append(tipo.upper())
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
    filename = f"GEA_{user['username']}_{periodo or 'todo'}.xlsx"
    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ─────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────
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
