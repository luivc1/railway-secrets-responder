# Team / colleague briefing

## EN
**Subject:** Action needed: rotate secrets stored on Railway

Team,

Railway disclosed on {{DISCLOSED}} that customer environment variables may have been
accessed. Railway asks all customers to roll every variable (API keys, database
credentials) and private registry credentials, and to review logs. Railway links it to
a campaign targeting AI inference providers, so AI keys go first.

We ran an audit (no secret values in it): {{p1_count}} P1, {{p2_count}} P2 items across
{{project_count}} projects. The checklist is attached ({{checklist_file}}).

How we rotate:
1. Create the new credential at the provider (link in the checklist).
2. Set it in Railway from your own terminal: `railway variable set NAME --stdin --skip-deploys -e <env> -s <service>`.
3. Update copies (local .env, GitHub secrets, other hosts).
4. Revoke the old one per the strategy in the checklist (REVOKE-NOW items: confirm with {{owner}} first).
5. Tick it off; we verify everything with the audit's baseline when deploys are back.

Never paste keys in chat, tickets or commits. Owner for questions: {{owner}}.

## ES
**Asunto:** Acción requerida: rotar los secretos guardados en Railway

Equipo:

Railway informó el {{DISCLOSED}} que las variables de entorno de sus clientes pudieron
haber sido accedidas. Railway pide a todos rotar cada variable (llaves de API,
credenciales de bases de datos) y las credenciales de registros privados, y revisar
los logs. Railway lo relaciona con una campaña contra proveedores de inferencia de IA,
así que las llaves de IA van primero.

Corrimos una auditoría (sin valores secretos): {{p1_count}} P1 y {{p2_count}} P2 en
{{project_count}} proyectos. Adjunto la lista ({{checklist_file}}).

Cómo rotamos:
1. Crear la credencial nueva en el proveedor (enlace en la lista).
2. Guardarla en Railway desde su propia terminal: `railway variable set NOMBRE --stdin --skip-deploys -e <env> -s <servicio>`.
3. Actualizar las copias (.env locales, secretos de GitHub, otros hosts).
4. Revocar la anterior según la estrategia de la lista (en REVOKE-NOW confirmar primero con {{owner}}).
5. Marcarla como hecha; verificamos todo con la línea base de la auditoría cuando vuelvan los despliegues.

Nunca peguen llaves en chats, tickets ni commits. Contacto: {{owner}}.
