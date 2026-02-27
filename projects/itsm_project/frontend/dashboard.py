import base64
import os
from collections import Counter
from pathlib import Path
from typing import Dict, List

import pandas as pd
import requests
import streamlit as st

# =============================
# Configuración básica
# =============================
st.set_page_config(page_title="ITSM L1 Automator", layout="wide")

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
LOGO_PATH = Path(__file__).resolve().parent.parent / "assets" / "logo.jpeg"

# =============================
# Branding / UI
# =============================
def load_logo_b64() -> str:
    if not LOGO_PATH.exists():
        return ""
    return base64.b64encode(LOGO_PATH.read_bytes()).decode("utf-8")


def inject_branding(logo_b64: str) -> None:
    logo_img = f"data:image/*;base64,{logo_b64}" if logo_b64 else ""
    logo_html = f'<img src="{logo_img}" alt="Logo" />' if logo_img else ""

    st.markdown(
        f"""
        <style>
            [data-testid="stAppViewContainer"] {{
                background: linear-gradient(180deg, #f5f7fb 0%, #eef1f7 100%);
            }}

            .block-container {{
                max-width: 1400px;
                padding-top: 1rem;
            }}

            [data-testid="stSidebar"] {{
                background-color: #0f1c2e;
            }}
            [data-testid="stSidebar"] * {{
                color: #f4f6fb !important;
            }}

            .l1-header {{
                display: flex;
                align-items: center;
                gap: 16px;
                padding: 14px 18px;
                background: linear-gradient(135deg, #0f1c2e 0%, #1f3b73 100%);
                color: #f7f9fc;
                border-radius: 14px;
                box-shadow: 0 10px 24px rgba(0,0,0,0.14);
                margin-bottom: 12px;
            }}

            .l1-header img {{
                height: 52px;
                width: auto;
                border-radius: 10px;
                background: #fff;
                padding: 6px 8px;
            }}

            .l1-header .title {{
                font-size: 22px;
                font-weight: 700;
                margin: 0;
            }}

            .l1-header .subtitle {{
                margin: 2px 0 0 0;
                opacity: 0.85;
                font-size: 14px;
            }}

            .stButton button {{
                border-radius: 10px;
                border: 1px solid rgba(15, 28, 46, 0.2);
                background: #1f3b73;
                color: #fff;
            }}

            .stButton button:hover {{
                background: #2a4b92;
            }}
        </style>

        <div class="l1-header">
            {logo_html}
            <div>
                <p class="title">ITSM L1 Automator</p>
                <p class="subtitle">Prueba técnica – Service Desk Nivel 1</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# =============================
# Backend calls
# =============================
def fetch_tickets() -> List[Dict]:
    try:
        r = requests.get(f"{API_BASE_URL}/tickets", timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Error obteniendo tickets: {e}")
        return []


def classify_tickets(tickets: List[Dict]) -> Dict[int, str]:
    results = {}
    for t in tickets:
        try:
            r = requests.post(
                f"{API_BASE_URL}/classify",
                json={"description": t.get("description", "")},
                timeout=10,
            )
            r.raise_for_status()
            results[t["id"]] = r.json().get("suggested_category", "Uncategorized")
        except Exception:
            results[t["id"]] = "Uncategorized"
    return results


def perform_close(ticket_id: int, resolution: str) -> None:
    try:
        requests.post(
            f"{API_BASE_URL}/actions/close-ticket",
            json={"ticket_id": ticket_id, "resolution": resolution},
            timeout=10,
        ).raise_for_status()
        st.success(f"Ticket #{ticket_id} cerrado")
    except Exception as e:
        st.error(f"No se pudo cerrar el ticket: {e}")


def perform_action(username: str, action: str) -> None:
    mapping = {
        "Reset password": "reset-password",
        "Activar usuario": "activate-user",
        "Desbloquear cuenta": "unlock-account",
    }
    endpoint = mapping[action]
    try:
        requests.post(
            f"{API_BASE_URL}/actions/{endpoint}",
            json={"username": username},
            timeout=10,
        ).raise_for_status()
        st.success(f"Acción ejecutada para {username}")
    except Exception as e:
        st.error(f"Error ejecutando acción: {e}")

# =============================
# Helpers
# =============================
def build_table(tickets: List[Dict], suggestions: Dict[int, str]) -> pd.DataFrame:
    rows = []
    for t in tickets:
        priority = t.get("priority", "")
        priority_ui = {
            "High": "🔴 High",
            "Medium": "🟠 Medium",
            "Low": "🟢 Low",
        }.get(priority, priority)

        status = t.get("status", "").lower()
        status_ui = {
            "open": "🟡 Open",
            "closed": "✅ Closed",
        }.get(status, status)

        rows.append(
            {
                "ID": t.get("id"),
                "Título": t.get("title"),
                "Usuario": t.get("user", ""),
                "Prioridad": priority_ui,
                "Estado": status_ui,
                "Categoría": t.get("category")
                or suggestions.get(t.get("id"), "Uncategorized"),
            }
        )

    return pd.DataFrame(rows)

# =============================
# App
# =============================
def main():
    inject_branding(load_logo_b64())

    if "tickets" not in st.session_state:
        with st.spinner("Cargando tickets..."):
            st.session_state.tickets = fetch_tickets()
    if "suggestions" not in st.session_state:
        st.session_state.suggestions = {}

    # Sidebar
    st.sidebar.header("Controles")

    if st.sidebar.button("Actualizar datos"):
        with st.spinner("Actualizando..."):
            st.session_state.tickets = fetch_tickets()

    if st.sidebar.button("Clasificar automáticamente", type="primary"):
        with st.spinner("Clasificando..."):
            st.session_state.suggestions = classify_tickets(st.session_state.tickets)

    tickets = st.session_state.tickets
    suggestions = st.session_state.suggestions

    # ---- Tickets Section
    st.markdown("""
    <div style="
        background:white;
        padding:16px 20px;
        border-radius:12px;
        margin-bottom:12px;
        box-shadow:0 6px 18px rgba(0,0,0,0.06);
    ">
        <h3 style="margin:0;">Tickets</h3>
        <p style="margin:4px 0 0 0; opacity:0.7;">
            Vista general de incidencias y su estado actual
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.dataframe(
        build_table(tickets, suggestions),
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("---")

    # ---- Acciones
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Cerrar ticket")
        if tickets:
            options = {
                f"#{t['id']} - {t['title'][:40]}": t["id"]
                for t in tickets
            }
            selected = st.selectbox("Ticket", options.keys())
            resolution = st.text_input("Resolución", "Ticket cerrado desde el dashboard")
            if st.button("Cerrar ticket", type="primary"):
                perform_close(options[selected], resolution)
                st.session_state.tickets = fetch_tickets()
        else:
            st.info("No hay tickets disponibles.")

    with col2:
        st.markdown("### Ejecutar acción")
        user = st.text_input("Usuario", placeholder="jperez")
        action = st.selectbox(
            "Acción",
            ["Reset password", "Activar usuario", "Desbloquear cuenta"],
        )
        if st.button("Ejecutar acción"):
            if user.strip():
                perform_action(user.strip(), action)
            else:
                st.warning("Ingresa un usuario.")

    st.markdown("---")

    # ---- Métricas
    st.subheader("Panel de métricas")

    statuses = [t.get("status", "").lower() for t in tickets]
    col_a, col_b, col_c = st.columns(3)
    col_a.metric("Tickets totales", len(tickets))
    col_b.metric("Abiertos", statuses.count("open"))
    col_c.metric("Cerrados", statuses.count("closed"))

if __name__ == "__main__":
    main()
