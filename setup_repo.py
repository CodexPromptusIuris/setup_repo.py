import os

# Definición de contenidos de los archivos

# 1. requirements.txt (Actualizado con TODAS las dependencias detectadas en tu código)
requirements_content = """streamlit
pandas
itsdangerous
sqlalchemy
pyotp
flask
flask-mail
"""

# 2. ley_21719_data.py (El módulo de análisis legal generado anteriormente)
ley_data_content = """
def get_norm_analysis():
    return {
        "titulo": "Ley N° 21.719: Protección y Tratamiento de Datos Personales",
        "metadatos": {
            "cve": "2583630",
            "fecha_publicacion": "2024-12-13",
            "fuente": "Diario Oficial de la República de Chile",
            "estado": "Vigente"
        },
        "resumen": (
            "Esta ley regula la protección y el tratamiento de los datos personales en Chile "
            "y crea la Agencia de Protección de Datos Personales. Modifica profundamente la "
            "Ley N° 19.628, estableciendo un nuevo estándar de cumplimiento."
        ),
        "principios_clave": [
            "Licitud y Lealtad",
            "Finalidad",
            "Proporcionalidad",
            "Calidad",
            "Responsabilidad (Accountability)"
        ],
        "impacto_organizacional": [
            "Creación de la Agencia de Protección de Datos Personales.",
            "Obligación de reportar brechas de seguridad.",
            "Nuevos derechos ARCO + Portabilidad.",
            "Multas actualizadas."
        ]
    }
"""

# 3. streamlit_app.py (Tu código PASC PRO + Integración visual de la Ley 21.719)
app_content = """
import os, json, hmac, hashlib
from datetime import datetime
from pathlib import Path
import streamlit as st
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import pyotp
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from flask_mail import Mail, Message
from flask import Flask

# Importar módulo legal
try:
    from ley_21719_data import get_norm_analysis
except ImportError:
    get_norm_analysis = None

# --- CONFIGURACIÓN E INICIALIZACIÓN ---
BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / 'instance'
INSTANCE_DIR.mkdir(exist_ok=True)

# Manejo robusto de secretos para Streamlit Cloud vs Local
SECRET_KEY = os.environ.get('PASC_SECRET_KEY', 'dev-secret-key-change-in-prod')
HMAC_KEY = os.environ.get('PASC_HMAC_KEY') or SECRET_KEY
DATABASE_URL = os.environ.get('DATABASE_URL') or f"sqlite:///{INSTANCE_DIR/'pasc_streamlit.db'}"

# Configuración de Correo (Valores por defecto dummy para evitar crash si no hay env vars)
MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
MAIL_PORT = int(os.environ.get('MAIL_PORT', 25))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'user')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'pass')
MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'false').lower() in ('1','true')
MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ('1','true')
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@pasc.example')

URL_SIGNER = URLSafeTimedSerializer(SECRET_KEY)
AUDIT_FILE = INSTANCE_DIR / 'pasc_audit_log_streamlit.jsonl'

# DB Setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class UserModel(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    totp_secret = Column(String(64), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Flask Mail Setup
app = Flask(__name__)
app.config.update(
    MAIL_SERVER=MAIL_SERVER, MAIL_PORT=MAIL_PORT, MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD, MAIL_USE_TLS=MAIL_USE_TLS, MAIL_USE_SSL=MAIL_USE_SSL,
    MAIL_DEFAULT_SENDER=MAIL_DEFAULT_SENDER
)
mail = Mail(app)

# --- FUNCIONES DE SEGURIDAD ---
def sign_record(record: str) -> str:
    return hmac.new(HMAC_KEY.encode(), record.encode(), hashlib.sha256).hexdigest()

def audit(event: str, details: dict):
    record = {'timestamp': datetime.utcnow().isoformat() + 'Z', 'event': event, 'details': details}
    line = json.dumps(record, ensure_ascii=False)
    signature = sign_record(line)
    try:
        with open(AUDIT_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'record': record, 'hmac': signature}, ensure_ascii=False) + '\\n')
    except Exception as e:
        print(f"Error escribiendo audit log: {e}")

def generate_email_token(email: str):
    return URL_SIGNER.dumps({'email': email, 'purpose': 'login'})

def verify_email_token(token: str, max_age=600):
    try:
        return URL_SIGNER.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None

def send_email_token(email: str, token: str):
    with app.app_context():
        try:
            msg = Message(subject='Tu código de acceso PASC PRO', recipients=[email])
            msg.body = f"Token de acceso: {token}"
            mail.send(msg)
            return True
        except Exception as e:
            st.error(f"Error SMTP: {e}")
            return False

# --- UI PRINCIPAL ---
st.set_page_config(page_title='PASC PRO - Auditor', layout='wide')

if 'authenticated' not in st.session_state:
    st.session_state.update({'authenticated': False, 'email': '', 'pending_token': ''})

# --- VISTA: DASHBOARD SEGURO (Post-Login) ---
if st.session_state['authenticated']:
    with st.sidebar:
        st.success(f"🔓 {st.session_state['email']}")
        if st.button('Cerrar sesión', type="primary"):
            audit('logout', {'email': st.session_state['email']})
            st.session_state['authenticated'] = False
            st.session_state['email'] = ''
            st.rerun()
    
    st.title("🛡️ PASC PRO: Panel de Auditoría")
    
    # Integración del Módulo Legal (Ley 21.719)
    if get_norm_analysis:
        data = get_norm_analysis()
        st.markdown("---")
        st.header(f"📋 {data['titulo']}")
        st.info(f"Estado: {data['metadatos']['estado']} | CVE: {data['metadatos']['cve']}")
        
        col1, col2 = st.columns([2, 1])
        with col1:
            st.subheader("Resumen Normativo")
            st.write(data['resumen'])
            st.write("**Principios Clave:**")
            for p in data['principios_clave']:
                st.markdown(f"- {p}")
        with col2:
            st.warning("⚠️ Impacto Organizacional")
            for imp in data['impacto_organizacional']:
                st.markdown(f"- {imp}")
    else:
        st.error("Módulo legal no encontrado.")
        
    st.stop()

# --- VISTA: LOGIN ---
st.title('🔒 PASC PRO - Acceso Seguro')

col1, col2 = st.columns(2)

with col1:
    st.markdown("#### Paso 1: Identificación")
    with st.form('request_form'):
        email_input = st.text_input('Correo corporativo')
        submit_req = st.form_submit_button('Solicitar acceso')

    if submit_req:
        email = email_input.strip().lower()
        if email:
            db = SessionLocal()
            user = db.query(UserModel).filter_by(email=email).first()
            if not user:
                user = UserModel(email=email, totp_secret=pyotp.random_base32())
                db.add(user)
                db.commit()
            
            token = generate_email_token(email)
            if send_email_token(email, token):
                audit('request_access', {'email': email})
                st.session_state['email'] = email
                st.session_state['pending_token'] = token
                st.success('Código enviado al correo.')
            else:
                # Fallback para demo si SMTP falla
                st.warning(f"[MODO DEMO] Token simulado: {token}")
                st.session_state['email'] = email
                st.session_state['pending_token'] = token
            db.close()

with col2:
    st.markdown("#### Paso 2: Verificación")
    with st.form('verify_form'):
        token_in = st.text_input('Código recibido')
        verify_btn = st.form_submit_button('Verificar Acceso')

    if verify_btn:
        token_in = token_in.strip()
        email = st.session_state.get('email')
        
        if not email:
            st.error("Complete el Paso 1 primero.")
        else:
            valid = False
            # Verificar Token Email
            if token_in == st.session_state.get('pending_token'):
                payload = verify_email_token(token_in)
                if payload and payload['email'] == email:
                    valid = True
            
            # Verificar TOTP (Alternativa)
            if not valid:
                db = SessionLocal()
                user = db.query(UserModel).filter_by(email=email).first()
                if user and pyotp.TOTP(user.totp_secret).verify(token_in, valid_window=1):
                    valid = True
                db.close()
            
            if valid:
                st.session_state['authenticated'] = True
                audit('login_success', {'email': email})
                st.rerun()
            else:
                st.error("Credenciales inválidas")
                audit('login_fail', {'email': email})
"""

# Función para generar los archivos
def create_project_structure():
    base_path = "pasc_pro_repo"
    if not os.path.exists(base_path):
        os.makedirs(base_path)
    
    files = {
        "requirements.txt": requirements_content,
        "ley_21719_data.py": ley_data_content,
        "streamlit_app.py": app_content
    }
    
    for filename, content in files.items():
        with open(os.path.join(base_path, filename), "w", encoding="utf-8") as f:
            f.write(content.strip())
            
    print(f"✅ Proyecto generado en la carpeta '{base_path}/'")
    print("   Archivos creados: requirements.txt, ley_21719_data.py, streamlit_app.py")

if __name__ == "__main__":
    create_project_structure()