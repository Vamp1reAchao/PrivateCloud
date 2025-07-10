require('dotenv').config({ path: '../.env' });
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const openpgp = require('openpgp');
const fs = require('fs');
const zlib = require('zlib');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const path = require('path');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'PGP File Storage API',
      version: '1.0.0',
      description: 'API для хранения зашифрованных файлов с PGP',
    },
    components: {
        securitySchemes: {
            bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            }
        }
    },
    security: [{
        bearerAuth: []
    }],
    servers: [
      {
        url: 'http://localhost:' + (process.env.PORT || 3000),
      },
    ],
  },
  apis: ['./app.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

const app = express();
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI);

// --- Mongoose схемы ---

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
  publicKey: String,
  privateKeyEncrypted: String, // зашифрованный приватный ключ
  salt: String,
  createdAt: { type: Date, default: Date.now }
});

const fileSchema = new mongoose.Schema({
  ownerId: mongoose.Types.ObjectId,
  filename: String,
  storedName: String,
  contentType: String,
  size: Number,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);

// --- Утилиты PGP ---

async function generatePGPKey(username, password) {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'rsa',
    rsaBits: 2048,
    userIDs: [{ name: username }],
    passphrase: password,
  });
  return { publicKey, privateKey };
}

async function encryptPrivateKey(privateKey, password) {
  // Мы уже сделали шифрование паролем при генерации (passphrase), 
  // но можно добавить свою обертку если надо
  return privateKey;
}

async function decryptPrivateKey(privateKeyArmored, passphrase) {
  try {
    const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
    const decryptedKey = await openpgp.decryptKey({
      privateKey,
      passphrase,
    });
    return decryptedKey;
  } catch (err) {
    console.error("Failed to decrypt private key:", err);
    return null;
  }
}

async function encryptFile(buffer, publicKeyArmored) {
  const compressedBuffer = zlib.deflateSync(buffer);
  const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: compressedBuffer }),
    encryptionKeys: publicKey,
    format: 'binary',
  });  
  return Buffer.from(encrypted);
}

async function decryptFile(encryptedBuffer, privateKey) {
  const message = await openpgp.readMessage({ binaryMessage: encryptedBuffer });
  const { data: decryptedCompressed } = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey,
    format: 'binary',
  });

  const decompressedBuffer = zlib.inflateSync(Buffer.from(decryptedCompressed));
  return decompressedBuffer;
}

// --- Middleware для аутентификации ---

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Роуты ---

/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: Регистрация и вход пользователей
 *   - name: Files
 *     description: Операции с файлами (загрузка, скачивание, список)
 */

 /**
  * @swagger
  * /register:
  *   post:
  *     summary: Регистрация нового пользователя
  *     tags: [Auth]
  *     requestBody:
  *       required: true
  *       content:
  *         application/json:
  *           schema:
  *             type: object
  *             required:
  *               - username
  *               - password
  *             properties:
  *               username:
  *                 type: string
  *                 example: user1
  *               password:
  *                 type: string
  *                 example: strongpassword
  *     responses:
  *       200:
  *         description: Пользователь успешно зарегистрирован
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 message:
  *                   type: string
  *                   example: User registered
  *       400:
  *         description: Ошибка валидации или пользователь уже существует
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 error:
  *                   type: string
  */
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const existing = await User.findOne({ username });
  if (existing) return res.status(400).json({ error: 'User already exists' });

  // Генерируем PGP ключи
  const { publicKey, privateKey } = await generatePGPKey(username, password);

  // Хешируем пароль для аутентификации
  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(password, salt);

  const user = new User({
    username,
    passwordHash,
    publicKey,
    privateKeyEncrypted: privateKey, // зашифрованный ключ уже с passphrase
    salt
  });

  await user.save();
  res.status(200).json({ message: 'User registered' });
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Логин пользователя и получение JWT токена
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 example: user1
 *               password:
 *                 type: string
 *                 example: strongpassword
 *     responses:
 *       200:
 *         description: Успешный логин с токеном
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *                 message:
 *                   type: string
 *                   example: Login successful
 *       400:
 *         description: Ошибка валидации
 *       401:
 *         description: Неверные данные для входа
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });

  const isMatch = bcrypt.compareSync(password, user.passwordHash);
  if (!isMatch) return res.status(401).json({ error: 'Invalid username or password' });

  const token = jwt.sign({ sub: user._id.toString() }, process.env.JWT_SECRET, { expiresIn: '24h' });
  res.status(200).json({ token, message: 'Login successful' });
});

/**
 * @swagger
 * /me:
 *   get:
 *     summary: Получение информации о текущем пользователе
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Информация о пользователе
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                   example: 609e1256f2d1a23c34c7c123
 *                 username:
 *                   type: string
 *                   example: user1
 *                 createdAt:
 *                   type: string
 *                   format: date-time
 *       401:
 *         description: Неавторизованный доступ
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 */
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('_id username createdAt');
    if (!user) return res.status(401).json({ error: 'User not found' });

    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Конфигурация multer для загрузки файлов
const storage = multer.memoryStorage();
const upload = multer({ storage });

/**
 * @swagger
 * /upload:
 *   post:
 *     summary: Загрузка файла с шифрованием PGP
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: password
 *         schema:
 *           type: string
 *         required: true
 *         description: Пароль для расшифровки приватного ключа пользователя
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Файл успешно загружен
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: File uploaded
 *       400:
 *         description: Ошибка валидации (нет файла или пароля)
 *       401:
 *         description: Ошибка аутентификации или неверный пароль
 */
app.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
  const password = req.query.password;
  if (!password) return res.status(400).json({ error: 'Password query param required' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const user = await User.findById(req.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });

  // Расшифровываем приватный ключ пользователя с паролем
  const privateKey = await decryptPrivateKey(user.privateKeyEncrypted, password);
  if (!privateKey) return res.status(401).json({ error: 'Invalid password for decrypting key' });

  // Шифруем файл публичным ключом пользователя
  const encryptedFileBuffer = await encryptFile(req.file.buffer, user.publicKey);

  const uniqueSuffix = Date.now() + '-' + crypto.randomBytes(6).toString('hex');
  const storedName = uniqueSuffix;
  const filePath = path.join(uploadDir, storedName);
  fs.writeFileSync(filePath, encryptedFileBuffer);

  const originalNameBuffer = Buffer.from(req.file.originalname, 'latin1');
  const originalName = originalNameBuffer.toString('utf8');

  const fileDoc = new File({
    ownerId: user._id,
    filename: originalName,
    storedName,
    contentType: req.file.mimetype,
    size: encryptedFileBuffer.length,
  });

  await fileDoc.save();
  res.status(200).json({ message: 'File uploaded' });
});

/**
 * @swagger
 * /download/{fileId}:
 *   get:
 *     summary: Скачивание и расшифровка файла
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: fileId
 *         schema:
 *           type: string
 *         required: true
 *         description: Идентификатор файла
 *       - in: query
 *         name: user_id
 *         schema:
 *           type: string
 *         required: true
 *         description: Идентификатор пользователя, владеющего файлом
 *       - in: query
 *         name: password
 *         schema:
 *           type: string
 *         required: true
 *         description: Пароль для расшифровки приватного ключа пользователя
 *     responses:
 *       200:
 *         description: Файл успешно расшифрован и возвращён
 *         content:
 *           application/octet-stream:
 *             schema:
 *               type: string
 *               format: binary
 *       400:
 *         description: Ошибка валидации параметров
 *       401:
 *         description: Ошибка аутентификации или неверный пароль
 *       404:
 *         description: Файл не найден или доступ запрещён
 *       500:
 *         description: Внутренняя ошибка сервера (файл отсутствует на диске)
 */
app.get('/download/:fileId', authMiddleware, async (req, res) => {
  const { fileId } = req.params;
  const { user_id, password } = req.query;
  if (req.userId !== user_id) return res.status(400).json({ error: 'Invalid userId' });
  if (!user_id || !password) return res.status(400).json({ error: 'user_id and password required' });

  const user = await User.findById(user_id);
  if (!user) return res.status(401).json({ error: 'User not found' });

  const fileDoc = await File.findOne({ _id: fileId, ownerId: user._id });
  if (!fileDoc) return res.status(404).json({ error: 'File not found or access denied' });

  // Расшифровываем приватный ключ пользователя
  const privateKey = await decryptPrivateKey(user.privateKeyEncrypted, password);
  if (!privateKey) return res.status(401).json({ error: 'Invalid password for decrypting key' });

  const filePath = path.join(uploadDir, fileDoc.storedName);
  if (!fs.existsSync(filePath)) return res.status(500).json({ error: 'File missing on server' });

  const encryptedFile = fs.readFileSync(filePath);
  const decryptedFile = await decryptFile(encryptedFile, privateKey);

  res.setHeader('Content-Type', fileDoc.contentType);
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileDoc.filename)}`);
  res.send(decryptedFile);
});

/**
 * @swagger
 * /list/{userId}:
 *   get:
 *     summary: Получение списка файлов пользователя
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         schema:
 *           type: string
 *         required: true
 *         description: Идентификатор пользователя
 *     responses:
 *       200:
 *         description: Список файлов
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                   ownerId:
 *                     type: string
 *                   filename:
 *                     type: string
 *                   storedName:
 *                     type: string
 *                   contentType:
 *                     type: string
 *                   size:
 *                     type: integer
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *       400:
 *         description: Неверный userId
 */
app.get('/list/:userId', authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.userId !== userId) return res.status(400).json({ error: 'Invalid userId' });
  if (!mongoose.Types.ObjectId.isValid(userId)) return res.status(400).json({ error: 'Invalid userId' });

  const files = await File.find({ ownerId: userId });
  res.status(200).json(files);
});

/**
 * @swagger
 * /file/{fileId}:
 *   delete:
 *     summary: Удаление файла по ID
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: fileId
 *         schema:
 *           type: string
 *         required: true
 *         description: Идентификатор файла
 *     responses:
 *       200:
 *         description: Информация о файле
 *         content:
 *           application/json:
 *             schema:
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                   ownerId:
 *                     type: string
 *                   filename:
 *                     type: string
 *                   storedName:
 *                     type: string
 *                   contentType:
 *                     type: string
 *                   size:
 *                     type: integer
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *       400:
 *         description: Неверный userId
 *       404:
 *         description: Файл не найден
 */
app.delete('/file/:fileId', authMiddleware, async (req, res) => {
  const { fileId } = req.params;
  const file = await File.findByIdAndDelete(fileId);
  if (!file) return res.status(404).json({ error: 'File not found' });

  const convertedUserId = new mongoose.Types.ObjectId(req.userId);
  if (!convertedUserId.equals(file.ownerId)) return res.status(400).json({ error: 'Invalid userId' });
  fs.unlink(`uploads/${file.storedName}`, (err) => {
    if (err) {
      console.error('Error deleting file:', err);
      return;
    }});
  res.status(200).json(file);
});

// Запуск сервера
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});