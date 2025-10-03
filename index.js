// === 0) Imports ===
import 'dotenv/config';
import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import { HfInference } from '@huggingface/inference';
import { DuckDuckGoSearch } from '@langchain/community/tools/duckduckgo_search';

// --- NOUVEL IMPORT POUR LE LOGGING ---
import pino from 'pino';

// === 1) Configuration et Initialisation ===
const PORT = process.env.PORT || 10000; // Utiliser le port de Render s'il est fourni
const hf = new HfInference(process.env.HUGGINGFACEHUB_API_TOKEN);
const searchTool = new DuckDuckGoSearch({ maxResults: 5 });

// --- CONFIGURATION DU LOGGER ---
// On crée un logger pour enregistrer des informations structurées
const logger = pino({
  level: 'info', // Niveau de log minimum (info, warn, error, fatal)
  transport: process.env.NODE_ENV !== 'production' 
    ? { target: 'pino-pretty' } // Format lisible en développement
    : undefined, // Format JSON en production (mieux pour les plateformes comme Render)
});


// === 2) Gestion de la Base de Données ===

let dbConnection;

async function getDbConnection() {
  // Si la connexion existe déjà, on la réutilise
  if (dbConnection) return dbConnection;

  try {
    logger.info('Tentative de lecture du certificat SSL...');
    const ca = fs.readFileSync('cert/ca.pem', 'utf-8');
    logger.info('Certificat SSL lu avec succès.');

    logger.info('Tentative de connexion à la base de données MySQL...');
    dbConnection = await mysql.createConnection({
      uri: process.env.DATABASE_URL,
      ssl: {
        ca: ca,
        rejectUnauthorized: true
      }
    });
    logger.info('Connexion à la base de données MySQL établie avec succès.');
    return dbConnection;

  } catch (error) {
    logger.error({
      err: error,
      message: error.message,
      stack: error.stack
    }, "Erreur critique lors de la connexion à la base de données.");
    // Si la connexion échoue, on lève l'erreur pour que le processus de démarrage s'arrête.
    throw error;
  }
}

async function initDb() {
  try {
    logger.info('Initialisation de la base de données...');
    const conn = await getDbConnection();
    await conn.execute(`CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, api_token VARCHAR(255) UNIQUE)`);
    await conn.execute(`CREATE TABLE IF NOT EXISTS memory (id INT AUTO_INCREMENT PRIMARY KEY, question TEXT NOT NULL, answer TEXT NOT NULL)`);
    logger.info('Tables "users" et "memory" vérifiées/créées avec succès.');
  } catch (error) {
    logger.error(error, "Erreur lors de l'initialisation des tables de la base de données.");
    throw error;
  }
}

// Fonctions de mémoire avec logs
async function searchMemory(question) {
  logger.info({ question }, 'Recherche de la question dans la mémoire SQL...');
  const conn = await getDbConnection();
  const [rows] = await conn.execute('SELECT answer FROM memory WHERE question = ?', [question]);
  if (rows.length > 0) {
    logger.info('Réponse trouvée dans la mémoire cache SQL.');
    return rows[0].answer;
  }
  logger.info('Aucune réponse trouvée dans la mémoire cache SQL.');
  return null;
}

async function addToMemory(question, answer) {
  logger.info({ question }, 'Ajout de la nouvelle réponse dans la mémoire SQL...');
  const conn = await getDbConnection();
  await conn.execute('INSERT INTO memory (question, answer) VALUES (?, ?)', [question, answer]);
  logger.info('Réponse sauvegardée avec succès.');
}


// === 3) Middlewares de Sécurité ===

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    logger.warn('Tentative d\'accès sans token JWT.');
    return res.status(401).json({ error: 'Token JWT manquant.' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn({ error: err.message }, 'Tentative d\'accès avec un token JWT invalide.');
      return res.status(403).json({ error: 'Token JWT invalide.' });
    }
    req.user = user;
    logger.info({ userId: user.id, username: user.username }, 'Token JWT validé avec succès.');
    next();
  });
};

const authenticateAPIKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    logger.warn('Tentative d\'accès sans clé API.');
    return res.status(401).json({ error: 'Clé API manquante dans le header X-API-Key' });
  }
  try {
    const conn = await getDbConnection();
    const [rows] = await conn.execute('SELECT id, username FROM users WHERE api_token = ?', [apiKey]);
    if (rows.length === 0) {
      logger.warn({ apiKeyAttempt: apiKey }, 'Tentative d\'accès avec une clé API invalide.');
      return res.status(403).json({ error: 'Clé API invalide' });
    }
    logger.info({ userId: rows[0].id, username: rows[0].username }, 'Clé API validée avec succès.');
    next();
  } catch (error) {
    logger.error(error, "Erreur serveur lors de la validation de la clé API.");
    res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
};


// === 4) Le Cerveau de l'IA ===

async function askAI(question) {
  logger.info({ question }, "Début du processus de réponse de l'IA.");

  // Étape 1 : Vérifier la mémoire cache SQL
  const cachedAnswer = await searchMemory(question);
  if (cachedAnswer) {
    return `(Mémoire SQL) ${cachedAnswer}`;
  }

  // Étape 2 : Chercher sur le web
  logger.info("Recherche sur le web avec DuckDuckGo...");
  const context = await searchTool.invoke(question);
  logger.info("Contexte de recherche web obtenu.");

  // Étape 3 : Appeler l'API Hugging Face
  const prompt = `En te basant sur ce contexte : ${context}\n\nRéponds à cette question : ${question}`;
  logger.info({ model: 'mistralai/Mixtral-8x7B-Instruct-v0.1' }, 'Appel de l\'API Hugging Face...');
  
  const response = await hf.textGeneration({
    model: 'mistralai/Mixtral-8x7B-Instruct-v0.1',
    inputs: prompt,
    parameters: { max_new_tokens: 250, temperature: 0.7, return_full_text: false }
  });
  logger.info('Réponse de Hugging Face reçue.');

  const newAnswer = response.generated_text.trim();

  // Étape 4 : Sauvegarder et retourner
  await addToMemory(question, newAnswer);
  return `(Recherche Web & IA) ${newAnswer}`;
}


// === 5) Le Serveur Web avec les Routes ===

const app = express();
app.use(cors());
app.use(express.json());

// Middleware pour logger chaque requête reçue
app.use((req, res, next) => {
  logger.info({ method: req.method, url: req.originalUrl, ip: req.ip }, 'Requête entrante');
  next();
});

// --- ROUTES PUBLIQUES (Authentification) ---
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Nom d'utilisateur et mot de passe requis" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const conn = await getDbConnection();
    await conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashedPassword]);
    logger.info({ username }, "Nouvel utilisateur créé avec succès.");
    res.status(201).json({ message: "Utilisateur créé avec succès" });
  } catch (err) {
    logger.error(err, "Erreur lors de la création de l'utilisateur.");
    res.status(500).json({ error: "Ce nom d'utilisateur est peut-être déjà pris" });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const conn = await getDbConnection();
    const [rows] = await conn.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      logger.warn({ username }, "Tentative de connexion échouée : utilisateur non trouvé.");
      return res.status(400).json({ error: "Identifiants invalides" });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      logger.warn({ username }, "Tentative de connexion échouée : mot de passe incorrect.");
      return res.status(400).json({ error: "Identifiants invalides" });
    }
    const accessToken = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logger.info({ username }, "Connexion réussie.");
    res.json({ accessToken });
  } catch (err) {
    logger.error(err, "Erreur serveur lors de la tentative de connexion.");
    res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// --- ROUTE PROTÉGÉE (Génération de clé API) ---
app.post("/user/api-token", authenticateJWT, async (req, res) => {
  try {
    const apiToken = "sk-" + crypto.randomBytes(24).toString("hex");
    const conn = await getDbConnection();
    await conn.execute("UPDATE users SET api_token=? WHERE id=?", [apiToken, req.user.id]);
    logger.info({ userId: req.user.id }, "Génération d'une nouvelle clé API.");
    res.json({ api_token: apiToken });
  } catch (err) {
    logger.error(err, "Erreur lors de la génération de la clé API.");
    res.status(500).json({ error: "Erreur lors de la génération de la clé API" });
  }
});

// --- ROUTE DE L'IA (Protégée par la clé API) ---
app.post('/ask', authenticateAPIKey, async (req, res) => {
  const { question } = req.body;
  if (!question) {
    return res.status(400).json({ error: 'La question est manquante.' });
  }
  try {
    const answer = await askAI(question);
    res.json({ answer: answer });
  } catch (error) {
    logger.error(error, "Erreur critique lors de l'exécution de la fonction askAI.");
    res.status(500).json({ error: "Une erreur interne est survenue lors de la génération de la réponse." });
  }
});

// --- GESTIONNAIRE D'ERREURS GLOBAL ---
// Ce middleware intercepte toutes les erreurs qui n'ont pas été gérées
app.use((err, req, res, next) => {
  logger.fatal(err, 'Une erreur non capturée est survenue !');
  res.status(500).json({ error: 'Une erreur interne inattendue est survenue.' });
});


// === 6) Démarrage du Serveur ===

async function startServer() {
  try {
    await initDb();
    app.listen(PORT, () => {
      logger.info(`\n>>> Serveur Node.js FINAL prêt ! Écoute sur le port ${PORT} <<<`);
    });
  } catch (error) {
    logger.fatal(error, "ERREUR FATALE AU DÉMARRAGE DU SERVEUR");
    process.exit(1); // Arrête le processus si la DB ou autre chose échoue au démarrage
  }
}

startServer();
