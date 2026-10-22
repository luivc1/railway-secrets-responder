# Client notice (first message)

## EN
**Subject:** Security update: Railway hosting incident and credential rotation

Hi {{client_name}},

Railway, the cloud platform that hosts {{app_name}}, disclosed on {{DISCLOSED}} that an
unauthorized party may have accessed the systems where it stores app settings,
including API keys and database passwords. Railway is asking every customer to
replace those credentials as a precaution.

What we are doing:
- Replacing the keys and passwords {{app_name}} uses, most sensitive first.
- Reviewing the related services for unusual activity.
- Railway has paused new deployments during its investigation, so some changes go
  live once Railway restores them. {{optional_downtime_note}}

{{client_action_or_nothing}}

We will update you by {{next_update_time}}.

{{your_name}}
{{company}}

## ES
**Asunto:** Actualización de seguridad: incidente en Railway y cambio de credenciales

Hola {{client_name}}:

Railway, la plataforma en la nube donde está alojada {{app_name}}, informó el
{{DISCLOSED}} que un tercero no autorizado pudo haber accedido a los sistemas donde
guarda la configuración de las aplicaciones, incluyendo llaves de API y contraseñas
de bases de datos. Railway pide a todos sus clientes reemplazar esas credenciales
como precaución.

Lo que estamos haciendo:
- Reemplazando las llaves y contraseñas que usa {{app_name}}, comenzando por las más sensibles.
- Revisando los servicios relacionados en busca de actividad inusual.
- Railway pausó los nuevos despliegues durante su investigación, por lo que algunos
  cambios se activarán cuando Railway los restablezca. {{optional_downtime_note}}

{{client_action_or_nothing}}

Le actualizaremos antes de {{next_update_time}}.

{{your_name}}
{{company}}
