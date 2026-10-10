# Huellitas de Cabungos — adopción con refugios y veterinarias

Node.js + Express + MongoDB. Las organizaciones se registran, el administrador las aprueba y luego publican sus mascotas con peso, raza, salud, vacunas y requisitos de adopción.

## Páginas
| Ruta | Quién la usa |
|---|---|
| `/` | Público: ver mascotas, filtrar y enviar solicitud de adopción |
| `/panel.html` | Refugios y veterinarias: registrarse, publicar y gestionar sus mascotas y solicitudes |
| `/admin.html` | Administrador de la plataforma (clave `ADMIN_KEY`): aprobar o suspender organizaciones |

## Flujo
1. Una organización se registra en `/panel.html` (queda **pendiente**).
2. El administrador entra a `/admin.html` y la pasa a **aprobada**.
3. La organización inicia sesión y publica mascotas. Las solicitudes de adopción le llegan a su panel.
4. Si una organización se **suspende**, sus mascotas dejan de verse y no puede entrar.

## Variables de entorno
| Variable | Para qué |
|---|---|
| `MONGODB_URI` | Cadena de conexión de MongoDB Atlas |
| `ADMIN_KEY` | Clave del administrador (en producción, mínimo 12 caracteres) |
| `SESSION_SECRET` | Firma las sesiones de las organizaciones. Usa un texto largo y aleatorio |
| `PORT` | Lo define el hosting |
| `DNS_SERVERS` | Opcional: `8.8.8.8,1.1.1.1` si tu red no resuelve `mongodb+srv` |

## Correr en tu computador
```powershell
npm install
$env:ADMIN_KEY="una-clave-larga-de-prueba"
$env:MONGODB_URI="mongodb+srv://USUARIO:CLAVE@cluster0.xxxxx.mongodb.net/Huellitas?appName=Cluster0"
npm start
```
Abre http://localhost:3000. La primera vez se cargan 5 mascotas de ejemplo de Proyecto Tawala y Riocanes.

## Publicar en internet (Render, como ejemplo)
1. Sube la carpeta a un repositorio **privado** de GitHub. `.gitignore` ya excluye `node_modules` y `.env`. Nunca subas claves ni cadenas de conexión.
2. En Render: **New → Web Service** → conecta el repositorio.
   - Build command: `npm install`
   - Start command: `npm start`
3. En **Environment** agrega `MONGODB_URI`, `ADMIN_KEY`, `SESSION_SECRET` (y `NODE_ENV=production`).
4. En Atlas, **Network Access**: permite `0.0.0.0/0`, porque el hosting no tiene IP fija. Por eso la contraseña del usuario de Atlas debe ser larga y única.
5. Cuando termine el despliegue, Render te da una dirección `https://...onrender.com`. Prueba `/`, `/panel.html` y `/admin.html`.
6. Los planes gratuitos suelen dormir el servicio tras un rato sin visitas. Revisa las condiciones actuales de cada plataforma. Si quieres tu propio dominio, se configura desde el hosting.

## Antes de abrirlo al público
- **Datos personales:** el sitio guarda nombre, teléfono y correo de quienes quieren adoptar y de las organizaciones. Publica una política de privacidad y confirma con un profesional lo que exige la ley de protección de datos de tu país (en Colombia, la Ley 1581 de 2012). Los formularios ya piden autorización y la guardan con fecha.
- **Aprobación de organizaciones:** revisa cada una antes de aprobarla (redes sociales, teléfono, referencias). Es la principal defensa contra publicaciones falsas.
- **Información de salud:** la declara cada organización. El sitio lo indica, pero la responsabilidad de que sea veraz es de quien publica.
- **Copias de seguridad:** activa los respaldos de Atlas si tu plan los incluye.

## Datos de pruebas anteriores
Las versiones anteriores guardaban en las colecciones `perritos` y `solicitudes`. Esta versión usa `mascotas`, `organizaciones`, `solicitudes_adopcion` y `fotos`. Puedes borrar las viejas desde Atlas (Explorador de datos).
