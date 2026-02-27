# ITSM L1 Automator

Proyecto práctico orientado a un rol de **Analista de Soporte TI / Service Desk Nivel 1**.  
Simula el ciclo básico de atención de incidencias: recepción de tickets, clasificación inicial, ejecución de acciones típicas L1 y cierre con resolución documentada.

El objetivo del proyecto es demostrar comprensión real de **flujos ITSM**, atención a usuarios y operaciones comunes de soporte en entornos corporativos.

---

## Flujo típico de soporte (L1)
1. Usuario reporta una incidencia (ticket).
2. El sistema sugiere una clasificación inicial según la descripción.
3. El analista ejecuta acciones comunes de Soporte TI Nivel 1.
4. El ticket se documenta y se cierra con una resolución.

---

## Qué demuestra este proyecto
- Gestión básica de tickets y estados de resolución.
- Ejecución de acciones típicas de Soporte TI Nivel 1 (reset de contraseña, activación de usuario, desbloqueo de cuenta).
- Clasificación inicial de incidencias por palabras clave.
- Visualización de tickets y métricas operativas en un dashboard.
- Consumo de servicios mediante API REST.

---

## Características principales
- Backend FastAPI con acciones L1 (reset de contraseña, activación de usuario, desbloqueo de cuenta y cierre de tickets).
- Motor de clasificación basado en palabras clave.
- Dashboard desarrollado en Streamlit con tabla de tickets y panel de métricas.
- Datos de ejemplo en formato JSON para tickets y usuarios.
- Endpoints listos para ser consumidos vía REST.

---

## Instalación y ejecución

### Backend (FastAPI)
1. Crear un entorno virtual (opcional) e instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```
2. Ejecutar el servidor:
   ```bash
   uvicorn backend.app:app --reload --port 8000
   ```
3. Documentación interactiva disponible en:  
   `http://localhost:8000/docs`

---

### Frontend (Streamlit)
1. En otra terminal, ejecutar el dashboard:
   ```bash
   streamlit run frontend/dashboard.py
   ```
2. Si el backend no corre en `http://localhost:8000`, exportar la variable de entorno:
   ```bash
   $env:API_BASE_URL="http://<host>:<port>"
   streamlit run frontend/dashboard.py
   ```


---

## Ejemplos de endpoints
- **Listar tickets**  
  `GET /tickets`

- **Clasificar ticket (sugerencia)**  
  `POST /classify`  
  Body:
  ```json
  { "description": "No puedo entrar al sistema" }
  ```

- **Reset de contraseña**  
  `POST /actions/reset-password`  
  Body:
  ```json
  { "username": "jperez" }
  ```

- **Activar usuario**  
  `POST /actions/activate-user`  
  Body:
  ```json
  { "username": "mlopez" }
  ```

- **Desbloquear cuenta**  
  `POST /actions/unlock-account`  
  Body:
  ```json
  { "username": "lmartinez" }
  ```

- **Cerrar ticket**  
  `POST /actions/close-ticket`  
  Body:
  ```json
  { "ticket_id": 1, "resolution": "Contraseña reiniciada" }
  ```

---

## Estructura del repositorio
```text
itsm-l1-automator/
├── backend/
│   ├── app.py
│   ├── classifier.py
│   ├── actions.py
│   ├── schemas.py
│   └── data/
│       ├── tickets.json
│       └── users.json
├── frontend/
│   └── dashboard.py
├── README.md
└── requirements.txt
```

---

## Roadmap (mejoras futuras)
- Persistencia con base de datos y auditoría de acciones.
- Autenticación básica en el backend y control de acceso.
- Creación y edición de tickets desde el dashboard.
- Integración con herramientas reales de ITSM (Jira, ServiceNow, etc.).
- Pruebas automatizadas (unitarias y end-to-end).

---

## Notas finales
- Los datos en JSON son simulados y pueden resetearse manualmente para nuevas pruebas.
- La clasificación utiliza una heurística simple por palabras clave; puede ampliarse con reglas más complejas o ML.
- El dashboard está pensado para demos locales; ajustar `API_BASE_URL` según el entorno de despliegue.
