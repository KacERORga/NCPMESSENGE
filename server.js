import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import pkg from 'pg';
const { Pool } = pkg;
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { 
    cors: { origin: "*" },
    connectionStateRecovery: {}
});

app.use(express.json());
app.use(express.static('public'));

// JWT секрет (переопределяется переменной окружения)
const JWT_SECRET = process.env.JWT_SECRET || 'ncp-messenger-super-secret-key-2024';
const PORT = process.env.PORT || 8080;

// ============ ПОДКЛЮЧЕНИЕ К БАЗЕ ДАННЫХ ============
let pool;

async function connectToDatabase() {
    try {
        pool = new Pool({
            host: process.env.POSTGRES_HOST || 'localhost',
            port: process.env.POSTGRES_PORT || 5432,
            user: process.env.POSTGRES_USER || 'postgres',
            password: process.env.POSTGRES_PASSWORD || '',
            database: process.env.POSTGRES_DB || 'postgres',
            ssl: process.env.POSTGRES_SSL === 'true' ? { rejectUnauthorized: false } : false,
            max: 20,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 2000,
        });
        
        // Проверка подключения
        await pool.query('SELECT NOW()');
        console.log('✅ PostgreSQL подключена');
        
        // Создание таблиц
        await initDatabase();
        return true;
    } catch (err) {
        console.error('❌ Ошибка подключения к PostgreSQL:', err.message);
        console.log('⚠️ Работаем без базы данных (сообщения не сохраняются)');
        return false;
    }
}

async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Таблица users готова');
    } catch (err) {
        console.error('❌ Ошибка создания users:', err.message);
    }
    
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                username VARCHAR(50) NOT NULL,
                text TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Таблица messages готова');
    } catch (err) {
        console.error('❌ Ошибка создания messages:', err.message);
    }
}

// ============ API ЭНДПОИНТЫ ============

// Регистрация
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }
    
    if (username.length < 3) {
        return res.status(400).json({ error: 'Имя пользователя минимум 3 символа' });
    }
    
    if (password.length < 4) {
        return res.status(400).json({ error: 'Пароль минимум 4 символа' });
    }
    
    try {
        const password_hash = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
            [username, email, password_hash]
        );
        res.json({ success: true, message: 'Регистрация успешна' });
    } catch (err) {
        if (err.code === '23505') {
            res.status(400).json({ error: 'Пользователь с таким именем или email уже существует' });
        } else {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
});

// Логин
app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    
    if (!login || !password) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }
    
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $1',
            [login]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password_hash);
        
        if (!valid) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            success: true,
            token,
            user: { id: user.id, username: user.username, email: user.email }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получение истории сообщений
app.get('/api/messages', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Нет токена' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        jwt.verify(token, JWT_SECRET);
        
        if (!pool) {
            return res.json([]);
        }
        
        const result = await pool.query(
            'SELECT id, user_id, username, text, timestamp FROM messages ORDER BY timestamp DESC LIMIT 100'
        );
        res.json(result.rows.reverse());
    } catch (err) {
        res.status(401).json({ error: 'Неверный токен' });
    }
});

// Проверка токена
app.get('/api/verify', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Нет токена' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, user: { id: decoded.id, username: decoded.username } });
    } catch (err) {
        res.status(401).json({ error: 'Неверный токен' });
    }
});

// Статистика (опционально)
app.get('/api/stats', async (req, res) => {
    if (!pool) {
        return res.json({ messages: 0, users: 0 });
    }
    
    try {
        const messagesResult = await pool.query('SELECT COUNT(*) FROM messages');
        const usersResult = await pool.query('SELECT COUNT(*) FROM users');
        res.json({
            messages: parseInt(messagesResult.rows[0].count),
            users: parseInt(usersResult.rows[0].count)
        });
    } catch (err) {
        res.json({ messages: 0, users: 0 });
    }
});

// ============ WEBSOCKET ============
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Нет токена авторизации'));
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.user = decoded;
        next();
    } catch (err) {
        next(new Error('Неверный токен'));
    }
});

io.on('connection', (socket) => {
    console.log(`✅ ${socket.user.username} подключился к чату`);
    
    // Отправляем приветствие
    socket.emit('connected', { message: 'Добро пожаловать в NCP Messenger!', user: socket.user });
    
    // Обработка сообщения
    socket.on('send_message', async (data) => {
        const { text } = data;
        
        if (!text || text.trim() === '') return;
        if (text.length > 5000) return;
        
        const messageData = {
            id: Date.now(),
            user_id: socket.user.id,
            username: socket.user.username,
            text: text.trim(),
            timestamp: new Date().toISOString()
        };
        
        // Сохраняем в БД, если доступна
        if (pool) {
            try {
                const result = await pool.query(
                    'INSERT INTO messages (user_id, username, text) VALUES ($1, $2, $3) RETURNING id',
                    [socket.user.id, socket.user.username, text.trim()]
                );
                messageData.id = result.rows[0].id;
            } catch (err) {
                console.error('Ошибка сохранения:', err.message);
            }
        }
        
        // Рассылаем всем пользователям
        io.emit('new_message', messageData);
    });
    
    // Обработка печатания
    socket.on('typing', (data) => {
        socket.broadcast.emit('user_typing', {
            username: socket.user.username,
            isTyping: data.isTyping
        });
    });
    
    // Отключение
    socket.on('disconnect', () => {
        console.log(`❌ ${socket.user.username} покинул чат`);
    });
});

// ============ ЗАПУСК СЕРВЕРА ============
// Запускаем подключение к БД и сервер
connectToDatabase().then(() => {
    httpServer.listen(PORT, () => {
        console.log(`╔══════════════════════════════════════╗`);
        console.log(`║     NCP MESSENGER - ЗАПУЩЕН        ║`);
        console.log(`╠══════════════════════════════════════╣`);
        console.log(`║  🚀 Порт: ${PORT}`);
        console.log(`║  💾 База: ${pool ? 'PostgreSQL ✓' : 'Нет (локальный режим)'}`);
        console.log(`║  🌐 Адрес: http://localhost:${PORT}`);
        console.log(`╚══════════════════════════════════════╝`);
    });
}).catch(() => {
    httpServer.listen(PORT, () => {
        console.log(`╔══════════════════════════════════════╗`);
        console.log(`║     NCP MESSENGER - ЗАПУЩЕН        ║`);
        console.log(`╠══════════════════════════════════════╣`);
        console.log(`║  🚀 Порт: ${PORT}`);
        console.log(`║  💾 База: Нет (локальный режим)`);
        console.log(`║  🌐 Адрес: http://localhost:${PORT}`);
        console.log(`╚══════════════════════════════════════╝`);
    });
});
