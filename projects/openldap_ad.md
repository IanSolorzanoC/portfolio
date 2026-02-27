# Implementación de OpenLDAP y Active Directory para la gestión de identidades

La gestión de identidades y accesos (IAM, por sus siglas en inglés) es un componente esencial en la ciberseguridad moderna. A través de políticas, procesos y tecnologías, permite a las organizaciones administrar usuarios, credenciales y permisos de manera centralizada, segura y eficiente.

En este trabajo se documenta la implementación de dos soluciones ampliamente utilizadas en entornos empresariales: **[OpenLDAP](https://www.openldap.org/)** en Linux Ubuntu y Active Directory en Windows Server.

---

## Importancia de la gestión de identidades

La adopción de un sistema IAM no solo fortalece la seguridad, también mejora la productividad y el cumplimiento normativo.

- **Eficiencia operativa**: unifica la gestión de accesos y facilita el uso de Single Sign-On (SSO).  
- **Reducción del riesgo humano**: las políticas de autenticación robustas previenen brechas de seguridad derivadas de errores de usuarios.  
- **Cumplimiento de normativas**: permite aplicar políticas de seguridad de forma centralizada y facilita las auditorías.  

**Imagen 1 (diagrama de IAM en la empresa)**  

---

## Implementación de OpenLDAP en Ubuntu Server

**Entorno de laboratorio**

- Ubuntu Server 22.04 LTS  
- 2 GB RAM, 1 vCPU, 127 GB HDD  
- Red NAT  

**Instalación y configuración básica**

1. Configuración inicial de zona horaria y apertura de puertos (22 para SSH, 389 para LDAP).  
2. Instalación con:  

   ```bash
   sudo apt install slapd ldap-utils
   ```
3. Definición del dominio dc=Cybersec2lab,dc=net.

4. Creación de Unidades Organizacionales (OUs) y grupos por departamentos como IT, RRHH y Ventas.
   
<img width="569" height="517" alt="image" src="https://github.com/user-attachments/assets/79719392-b967-4026-86ef-9cb0bdb7b4df" />

## Políticas de contraseñas

Se habilitó el módulo ppolicy con las siguientes condiciones:

- Contraseñas de al menos 8 caracteres.

- Historial de 5 contraseñas previas.

- Cambio obligatorio en el primer inicio de sesión.

- Caducidad configurada para las contraseñas.


## Administración con phpLDAPadmin

La gestión se realizó mediante la interfaz gráfica **phpLDAPadmin**, accediendo a través de un **túnel SSH** en el puerto local `8080`.  
Durante el proceso se validaron las políticas de seguridad al crear usuarios de prueba.


### 1. Preparación del servidor

- Configuración del **nombre de equipo** e **IP estática**.  
- Habilitación de puertos esenciales:
  - **LDAP (389)**
  - **Kerberos (88)**
  - **DNS (53)**
  - **RDP (3389)**


### 2. Instalación y configuración

1. Instalación de Active Directory Domain Services.  
2. Promoción del servidor a Domain Controller, creando un nuevo bosque y dominio.  
3. Configuración de la contraseña para el modo de recuperación DSRM.  

<img width="624" height="431" alt="image" src="https://github.com/user-attachments/assets/32254deb-6043-4540-8769-41f4e4451f0b" />



### 3. Organización y políticas

- Se crearon OUs para los departamentos:
  - IT  
  - RRHH  
  - Ventas  
  - Contabilidad  
  - Gerencia  

- Los usuarios se agruparon en grupos globales de acuerdo a cada departamento.  

### Políticas aplicadas mediante Group Policy Management

- Contraseñas de mínimo 8 caracteres con complejidad habilitada.  
- Historial de 5 contraseñas previas.  
- Caducidad cada 90 días.  

<img width="266" height="163" alt="Captura de pantalla 2025-09-06 214604" src="https://github.com/user-attachments/assets/b192bc65-0c8e-465a-9818-c8b972a6c7b0" />


## Administración remota

La administración se validó con la instalación de RSAT (Remote Server Administration Tools)
 y el uso de RDP, comprobando la gestión remota de usuarios y políticas.


<img width="1536" height="1024" alt="686286b2-2a73-4ea0-80eb-faa8cdd6ee66" src="https://github.com/user-attachments/assets/59f13205-f779-46ff-b0a1-f103b1332aab" />


---

## Conclusiones

La implementación de OpenLDAP y Active Directory demuestra cómo ambas tecnologías cumplen con el objetivo de centralizar la gestión de identidades, aunque cada una con un enfoque distinto:

- OpenLDAP ofrece flexibilidad, personalización y es ideal en entornos Linux con un fuerte enfoque en software libre.

- Active Directory se integra de manera natural en ecosistemas Windows y ofrece herramientas de gestión más intuitivas.

Ambas soluciones representan pilares en la estrategia de ciberseguridad de cualquier organización que busque robustecer el control de accesos e identidades.
