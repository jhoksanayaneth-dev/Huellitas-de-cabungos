if (process.env.DNS_SERVERS) require('dns').setServers(process.env.DNS_SERVERS.split(','));
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/huellitas';
if (!ADMIN_KEY) {
  console.error('Falta la variable ADMIN_KEY. Ejemplo: ADMIN_KEY=mi-clave-secreta npm start');
  process.exit(1);
}
if (process.env.NODE_ENV === 'production' && ADMIN_KEY.length < 12) {
  console.error('En producción, ADMIN_KEY debe tener al menos 12 caracteres.');
  process.exit(1);
}
// Firma las sesiones de las organizaciones. Mejor definir SESSION_SECRET aparte en producción.
const SESSION_SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update('sesion:' + ADMIN_KEY).digest('hex');

// ---------- MODELOS ----------
const { Schema } = mongoose;
const ObjectId = Schema.Types.ObjectId;

// Devuelven "id" en lugar de "_id" y ocultan campos internos
const json = (...ocultos) => ({
  versionKey: false,
  transform: (doc, ret) => { ret.id = String(ret._id); delete ret._id; ocultos.forEach(c => delete ret[c]); return ret; }
});
const tri = { type: Boolean, default: null }; // true = sí, false = no, null = sin dato

const organizacionSchema = new Schema({
  nombre: { type: String, required: true, trim: true, maxlength: 100 },
  tipo: { type: String, enum: ['refugio', 'veterinaria', 'fundacion'], required: true },
  correo: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false },
  telefono: { type: String, required: true, trim: true },
  ciudad: { type: String, required: true, trim: true, maxlength: 80 },
  direccion: { type: String, default: '', trim: true, maxlength: 200 },
  descripcion: { type: String, default: '', trim: true, maxlength: 500 },
  estado: { type: String, enum: ['pendiente', 'aprobada', 'suspendida'], default: 'pendiente' },
  consentimiento: { type: Date, required: true }
}, { timestamps: true, toJSON: json('passwordHash') });

const mascotaSchema = new Schema({
  organizacion: { type: ObjectId, ref: 'Organizacion', default: null, index: true },
  refugio: { type: String, required: true, trim: true },   // nombre visible de quien publica
  ciudad: { type: String, required: true, trim: true },
  especie: { type: String, enum: ['perro', 'gato', 'otro'], default: 'perro' },
  nombre: { type: String, required: true, trim: true, maxlength: 80 },
  raza: { type: String, required: true, trim: true, maxlength: 200 },
  sexo: { type: String, enum: ['macho', 'hembra', 'sin dato'], default: 'sin dato' },
  edad: { type: String, default: '', trim: true, maxlength: 40 },
  pesoKg: { type: Number, default: null, min: 0.1, max: 120 },
  peso: { type: String, default: '' },
  tamano: { type: String, enum: ['pequeño', 'mediano', 'grande', null], default: null },
  personalidad: { type: String, required: true, trim: true, maxlength: 1000 },
  // Salud (declarada por quien publica)
  sano: tri, vacunasAlDia: tri, esterilizado: tri, desparasitado: tri,
  vacunasDetalle: { type: String, default: '', trim: true, maxlength: 300 },
  condicionesSalud: { type: String, default: '', trim: true, maxlength: 500 },
  // Convivencia
  buenoConNinos: tri, buenoConPerros: tri, buenoConGatos: tri,
  requisitos: { type: [String], default: [] },
  foto: { type: String, default: null },
  fotoId: { type: ObjectId, default: null, select: false },
  disponible: { type: Boolean, default: true },
  suspendida: { type: Boolean, default: false } // true si la organización fue suspendida
}, { timestamps: true, toJSON: json('fotoId') });

const fotoSchema = new Schema({
  data: { type: Buffer, required: true },
  mime: { type: String, required: true }
}, { timestamps: true });

const solicitudSchema = new Schema({
  mascota: { type: ObjectId, ref: 'Mascota', required: true, index: true },
  organizacion: { type: ObjectId, ref: 'Organizacion', default: null, index: true },
  nombre: { type: String, required: true, trim: true },
  telefono: { type: String, required: true, trim: true },
  correo: { type: String, default: '', trim: true },
  mensaje: { type: String, default: '', trim: true },
  consentimiento: { type: Date, required: true },
  estado: { type: String, enum: ['pendiente', 'contactado', 'aprobada', 'rechazada'], default: 'pendiente' }
}, { timestamps: true });

const Organizacion = mongoose.model('Organizacion', organizacionSchema, 'organizaciones');
const Mascota = mongoose.model('Mascota', mascotaSchema, 'mascotas');
const Foto = mongoose.model('Foto', fotoSchema, 'fotos');
const Solicitud = mongoose.model('Solicitud', solicitudSchema, 'solicitudes_adopcion');

// ---------- UTILIDADES ----------
const hash = (s) => crypto.createHash('sha256').update(String(s)).digest();
const esAdmin = (req) => crypto.timingSafeEqual(hash(req.get('x-admin-key') || ''), hash(ADMIN_KEY));
const soloAdmin = (req, res, next) => (esAdmin(req) ? next() : res.status(401).json({ error: 'No autorizado' }));
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const escaparRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const noEncontrado = (res, txt) => res.status(404).json({ error: txt });
const idValido = (id) => mongoose.isValidObjectId(id);
const HASH_FALSO = bcrypt.hashSync('contraseña-falsa', 10); // para que el login tarde igual si el correo no existe

// Límite de intentos por IP
function limitador(max, ventanaMs, mensaje) {
  const registro = new Map();
  setInterval(() => registro.clear(), ventanaMs * 2).unref();
  return (req, res, next) => {
    const ahora = Date.now();
    const lista = (registro.get(req.ip) || []).filter(t => ahora - t < ventanaMs);
    if (lista.length >= max) return res.status(429).json({ error: mensaje });
    lista.push(ahora);
    registro.set(req.ip, lista);
    next();
  };
}
const limitarSolicitudes = limitador(5, 3600000, 'Demasiadas solicitudes. Intenta más tarde.');
const limitarRegistro = limitador(5, 3600000, 'Demasiados registros desde esta conexión. Intenta más tarde.');
const limitarLogin = limitador(10, 900000, 'Demasiados intentos. Espera unos minutos.');

// Fotos: se guardan dentro de MongoDB
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype)) return cb(null, true);
    const e = new Error('Solo se permiten imágenes JPG, PNG o WebP');
    e.status = 400;
    cb(e);
  }
});
const esImagenReal = (b) =>
  (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) ||
  (b.slice(0, 4).toString('hex') === '89504e47') ||
  (b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP');

async function guardarFoto(file) {
  if (!esImagenReal(file.buffer)) {
    const e = new Error('El archivo no es una imagen válida');
    e.status = 400;
    throw e;
  }
  return Foto.create({ data: file.buffer, mime: file.mimetype });
}

// ---------- LÓGICA DE MASCOTAS ----------
const tamanoPorPeso = (kg) => (kg < 10 ? 'pequeño' : kg <= 25 ? 'mediano' : 'grande');
const triestado = (v) => {
  if (v === undefined) return undefined; // no vino en la petición: no se toca
  if (['si', 'sí', 'true', '1', true].includes(v)) return true;
  if (['no', 'false', '0', false].includes(v)) return false;
  return null;
};

function aplicarCampos(m, b) {
  for (const c of ['nombre', 'raza', 'personalidad', 'edad', 'vacunasDetalle', 'condicionesSalud'])
    if (b[c] !== undefined) m[c] = String(b[c]);
  if (b.especie) m.especie = b.especie;
  if (b.sexo) m.sexo = b.sexo;
  if (b.pesoKg !== undefined && b.pesoKg !== '') {
    const n = Number(String(b.pesoKg).replace(',', '.'));
    m.pesoKg = n;
    m.peso = `${n} kg`;
    m.tamano = Number.isFinite(n) ? tamanoPorPeso(n) : null;
  }
  for (const c of ['sano', 'vacunasAlDia', 'esterilizado', 'desparasitado', 'buenoConNinos', 'buenoConPerros', 'buenoConGatos']) {
    const v = triestado(b[c]);
    if (v !== undefined) m[c] = v;
  }
  if (b.requisitos !== undefined) {
    const lista = Array.isArray(b.requisitos) ? b.requisitos : String(b.requisitos).split('\n');
    m.requisitos = lista.map(s => String(s).trim().slice(0, 150)).filter(Boolean).slice(0, 12);
  }
}

function filtrosPublicos(q) {
  const f = { disponible: true, suspendida: { $ne: true } };
  if (['perro', 'gato', 'otro'].includes(q.especie)) f.especie = q.especie;
  if (['macho', 'hembra'].includes(q.sexo)) f.sexo = q.sexo;
  if (['pequeño', 'mediano', 'grande'].includes(q.tamano)) f.tamano = q.tamano;
  if (typeof q.ciudad === 'string' && q.ciudad.trim())
    f.ciudad = new RegExp('^' + escaparRegex(q.ciudad.trim()) + '$', 'i');
  for (const [param, campo] of [['vacunas', 'vacunasAlDia'], ['esterilizado', 'esterilizado'], ['sano', 'sano'], ['ninos', 'buenoConNinos']])
    if (q[param] === '1') f[campo] = true;
  const min = parseFloat(q.pesoMin), max = parseFloat(q.pesoMax);
  if (!isNaN(min) || !isNaN(max)) {
    f.pesoKg = {};
    if (!isNaN(min)) f.pesoKg.$gte = min;
    if (!isNaN(max)) f.pesoKg.$lte = max;
  }
  const t = typeof q.q === 'string' ? q.q.trim() : '';
  if (t) {
    const rx = new RegExp(escaparRegex(t), 'i');
    f.$or = [{ nombre: rx }, { raza: rx }, { personalidad: rx }, { refugio: rx }];
  }
  return f;
}

async function crearMascota(req, res) {
  const b = req.body || {};
  const org = req.org;
  const faltan = [];
  for (const c of ['nombre', 'raza', 'edad', 'personalidad', 'pesoKg'])
    if (!String(b[c] || '').trim()) faltan.push(c);
  if (!['perro', 'gato', 'otro'].includes(b.especie)) faltan.push('especie');
  if (!['macho', 'hembra'].includes(b.sexo)) faltan.push('sexo');
  if (!String(b.requisitos || '').trim()) faltan.push('requisitos');
  if (faltan.length) return res.status(400).json({ error: 'Faltan campos: ' + faltan.join(', ') });

  const m = new Mascota({ organizacion: org._id, refugio: org.nombre, ciudad: org.ciudad });
  aplicarCampos(m, b);
  await m.validate(); // valida antes de guardar la foto, para no dejar fotos huérfanas
  if (req.file) {
    const foto = await guardarFoto(req.file);
    m.foto = '/api/fotos/' + foto._id;
    m.fotoId = foto._id;
  }
  await m.save();
  res.status(201).json(m);
}

async function actualizarMascota(req, res, filtro) {
  const m = idValido(req.params.id) && await Mascota.findOne({ _id: req.params.id, ...filtro }).select('+fotoId');
  if (!m) return noEncontrado(res, 'Mascota no encontrada');
  const b = req.body || {};
  aplicarCampos(m, b);
  if (b.disponible !== undefined) m.disponible = ['1', 'true', 1, true].includes(b.disponible);
  await m.validate();
  if (req.file) {
    const nueva = await guardarFoto(req.file);
    if (m.fotoId) await Foto.findByIdAndDelete(m.fotoId);
    m.foto = '/api/fotos/' + nueva._id;
    m.fotoId = nueva._id;
  }
  await m.save();
  res.json(m);
}

async function borrarMascota(req, res, filtro) {
  const m = idValido(req.params.id) && await Mascota.findOne({ _id: req.params.id, ...filtro }).select('+fotoId');
  if (!m) return noEncontrado(res, 'Mascota no encontrada');
  if (m.fotoId) await Foto.findByIdAndDelete(m.fotoId);
  await Solicitud.deleteMany({ mascota: m._id });
  await m.deleteOne();
  res.status(204).end();
}

const mapSol = (s) => ({
  id: String(s._id),
  mascota_id: s.mascota ? String(s.mascota._id) : null,
  mascota_nombre: s.mascota ? s.mascota.nombre : '(eliminada)',
  organizacion_nombre: s.organizacion ? s.organizacion.nombre : '',
  nombre: s.nombre, telefono: s.telefono, correo: s.correo, mensaje: s.mensaje,
  estado: s.estado, fecha: s.createdAt
});
const listarSolicitudes = async (filtro) =>
  (await Solicitud.find(filtro).sort({ createdAt: -1 }).populate('mascota', 'nombre').populate('organizacion', 'nombre')).map(mapSol);

async function cambiarEstadoSolicitud(req, res, filtro) {
  if (!Solicitud.schema.path('estado').enumValues.includes(req.body.estado))
    return res.status(400).json({ error: 'Estado no válido' });
  const s = idValido(req.params.id) && await Solicitud.findOneAndUpdate({ _id: req.params.id, ...filtro }, { estado: req.body.estado });
  s ? res.json({ ok: true }) : noEncontrado(res, 'Solicitud no encontrada');
}

// ---------- AUTENTICACIÓN DE ORGANIZACIONES ----------
const firmar = (org) => jwt.sign({ sub: String(org._id) }, SESSION_SECRET, { expiresIn: '7d' });
const soloOrg = ah(async (req, res, next) => {
  let datos;
  try { datos = jwt.verify((req.get('authorization') || '').replace(/^Bearer /, ''), SESSION_SECRET); }
  catch { return res.status(401).json({ error: 'Sesión no válida. Inicia sesión de nuevo.' }); }
  const org = idValido(datos.sub) && await Organizacion.findById(datos.sub);
  if (!org || org.estado === 'suspendida') return res.status(401).json({ error: 'Cuenta no disponible' });
  req.org = org;
  next();
});
const soloAprobada = (req, res, next) =>
  req.org.estado === 'aprobada' ? next() : res.status(403).json({ error: 'Tu organización aún está en revisión. Podrás publicar cuando sea aprobada.' });

// ---------- APP ----------
const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' });
  next();
});
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ----- Público -----
app.get('/api/fotos/:id', ah(async (req, res) => {
  const f = idValido(req.params.id) && await Foto.findById(req.params.id);
  if (!f) return noEncontrado(res, 'Foto no encontrada');
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.type(f.mime).send(f.data);
}));

app.get('/api/mascotas', ah(async (req, res) => {
  res.json(await Mascota.find(filtrosPublicos(req.query)).sort({ createdAt: -1 }).limit(200));
}));

app.get('/api/ciudades', ah(async (req, res) => {
  const ciudades = await Mascota.distinct('ciudad', { disponible: true, suspendida: { $ne: true } });
  res.json(ciudades.sort((a, b) => a.localeCompare(b, 'es')));
}));

app.get('/api/mascotas/:id', ah(async (req, res) => {
  const m = idValido(req.params.id) && await Mascota.findOne({ _id: req.params.id, disponible: true, suspendida: { $ne: true } });
  m ? res.json(m) : noEncontrado(res, 'Mascota no encontrada');
}));

app.post('/api/solicitudes', limitarSolicitudes, ah(async (req, res) => {
  const b = req.body || {};
  const nombre = String(b.nombre || '').trim();
  const telefono = String(b.telefono || '').trim();
  const correo = String(b.correo || '').trim();
  const mensaje = String(b.mensaje || '').trim();
  if (nombre.length < 2 || nombre.length > 100) return res.status(400).json({ error: 'Escribe tu nombre' });
  if (!/^[0-9+()\s-]{7,20}$/.test(telefono)) return res.status(400).json({ error: 'Teléfono no válido' });
  if (correo && !/^\S+@\S+\.\S+$/.test(correo)) return res.status(400).json({ error: 'Correo no válido' });
  if (mensaje.length > 1000) return res.status(400).json({ error: 'El mensaje es muy largo' });
  if (b.consentimiento !== true) return res.status(400).json({ error: 'Debes autorizar el uso de tus datos para contactarte' });
  const m = idValido(b.mascota_id) && await Mascota.findOne({ _id: b.mascota_id, disponible: true, suspendida: { $ne: true } });
  if (!m) return noEncontrado(res, 'Esa mascota ya no está disponible');
  const s = await Solicitud.create({
    mascota: m._id, organizacion: m.organizacion, nombre, telefono, correo, mensaje, consentimiento: new Date()
  });
  res.status(201).json({ ok: true, id: String(s._id) });
}));

// ----- Organizaciones (refugios y veterinarias) -----
app.post('/api/org/registro', limitarRegistro, ah(async (req, res) => {
  const b = req.body || {};
  const correo = String(b.correo || '').trim().toLowerCase();
  const password = String(b.password || '');
  if (String(b.nombre || '').trim().length < 2) return res.status(400).json({ error: 'Escribe el nombre de la organización' });
  if (!['refugio', 'veterinaria', 'fundacion'].includes(b.tipo)) return res.status(400).json({ error: 'Elige el tipo de organización' });
  if (!/^\S+@\S+\.\S+$/.test(correo)) return res.status(400).json({ error: 'Correo no válido' });
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres' });
  if (!/^[0-9+()\s-]{7,20}$/.test(String(b.telefono || '').trim())) return res.status(400).json({ error: 'Teléfono no válido' });
  if (String(b.ciudad || '').trim().length < 2) return res.status(400).json({ error: 'Escribe la ciudad' });
  if (b.consentimiento !== true) return res.status(400).json({ error: 'Debes aceptar el tratamiento de datos' });
  await Organizacion.create({
    nombre: b.nombre, tipo: b.tipo, correo, passwordHash: await bcrypt.hash(password, 10),
    telefono: b.telefono, ciudad: b.ciudad, direccion: b.direccion || '', descripcion: b.descripcion || '',
    consentimiento: new Date()
  });
  res.status(201).json({ ok: true });
}));

app.post('/api/org/login', limitarLogin, ah(async (req, res) => {
  const b = req.body || {};
  const org = await Organizacion.findOne({ correo: String(b.correo || '').trim().toLowerCase() }).select('+passwordHash');
  const ok = await bcrypt.compare(String(b.password || ''), org ? org.passwordHash : HASH_FALSO);
  if (!org || !ok) return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
  if (org.estado === 'suspendida') return res.status(403).json({ error: 'Esta cuenta está suspendida' });
  res.json({ token: firmar(org), organizacion: org });
}));

app.get('/api/org/yo', soloOrg, (req, res) => res.json(req.org));

app.get('/api/org/mascotas', soloOrg, ah(async (req, res) =>
  res.json(await Mascota.find({ organizacion: req.org._id }).sort({ createdAt: -1 }))));
app.post('/api/org/mascotas', soloOrg, soloAprobada, upload.single('foto'), ah(crearMascota));
app.put('/api/org/mascotas/:id', soloOrg, soloAprobada, upload.single('foto'),
  ah((req, res) => actualizarMascota(req, res, { organizacion: req.org._id })));
app.delete('/api/org/mascotas/:id', soloOrg, ah((req, res) => borrarMascota(req, res, { organizacion: req.org._id })));

app.get('/api/org/solicitudes', soloOrg, ah(async (req, res) => res.json(await listarSolicitudes({ organizacion: req.org._id }))));
app.patch('/api/org/solicitudes/:id', soloOrg, ah((req, res) => cambiarEstadoSolicitud(req, res, { organizacion: req.org._id })));

// ----- Administrador de la plataforma (header x-admin-key) -----
app.get('/api/admin/organizaciones', soloAdmin, ah(async (req, res) =>
  res.json(await Organizacion.find().sort({ createdAt: -1 }))));

app.patch('/api/admin/organizaciones/:id', soloAdmin, ah(async (req, res) => {
  if (!['pendiente', 'aprobada', 'suspendida'].includes(req.body.estado))
    return res.status(400).json({ error: 'Estado no válido' });
  const r = idValido(req.params.id) && await Organizacion.updateOne({ _id: req.params.id }, { estado: req.body.estado });
  if (!r || !r.matchedCount) return noEncontrado(res, 'Organización no encontrada');
  await Mascota.updateMany({ organizacion: req.params.id }, { suspendida: req.body.estado === 'suspendida' });
  res.json({ ok: true });
}));

app.get('/api/admin/mascotas', soloAdmin, ah(async (req, res) => res.json(await Mascota.find().sort({ createdAt: -1 }))));
app.put('/api/admin/mascotas/:id', soloAdmin, upload.single('foto'), ah((req, res) => actualizarMascota(req, res, {})));
app.delete('/api/admin/mascotas/:id', soloAdmin, ah((req, res) => borrarMascota(req, res, {})));
app.get('/api/admin/solicitudes', soloAdmin, ah(async (req, res) => res.json(await listarSolicitudes({}))));
app.patch('/api/admin/solicitudes/:id', soloAdmin, ah((req, res) => cambiarEstadoSolicitud(req, res, {})));

// ---------- ERRORES ----------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: 'Foto no válida (máximo 3 MB)' });
  if (err.name === 'ValidationError') return res.status(400).json({ error: 'Datos no válidos: ' + Object.keys(err.errors).join(', ') });
  if (err.name === 'CastError') return res.status(400).json({ error: 'Dato no válido: ' + err.path });
  if (err.code === 11000) return res.status(409).json({ error: 'Ese correo ya está registrado' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON no válido' });
  if (err.status) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// ---------- ARRANQUE ----------
async function iniciar() {
  await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
  console.log('Conectado a MongoDB');
  await Organizacion.init();

  // Carga inicial: mascotas de ejemplo de Proyecto Tawala y Riocanes
  if ((await Mascota.countDocuments()) === 0) {
    const { candidatos, refugio, ubicacion } = JSON.parse(fs.readFileSync(path.join(__dirname, 'seed', 'perritos.json'), 'utf8'));
    const promedio = (txt) => {
      const n = (String(txt).match(/\d+([.,]\d+)?/g) || []).map(x => Number(x.replace(',', '.')));
      return n.length ? Math.round((n.reduce((a, b) => a + b, 0) / n.length) * 10) / 10 : null;
    };
    await Mascota.insertMany(candidatos.map(p => {
      const kg = promedio(p.peso);
      return {
        refugio, ciudad: String(ubicacion).split(',')[0].trim(), especie: 'perro',
        nombre: p.nombre, raza: p.raza, personalidad: p.personalidad,
        peso: String(p.peso).replace(/\s*\(.*\)\s*$/, ''), pesoKg: kg, tamano: kg ? tamanoPorPeso(kg) : null
      };
    }));
    console.log(`Base de datos creada con ${candidatos.length} mascotas iniciales.`);
  }
  app.listen(PORT, () => console.log(`Huellitas de Cabungos en http://localhost:${PORT}`));
}

iniciar().catch((e) => {
  console.error('No se pudo conectar a MongoDB:', e.message);
  console.error('Revisa MONGODB_URI (usuario, contraseña y acceso de red en Atlas).');
  process.exit(1);
});
