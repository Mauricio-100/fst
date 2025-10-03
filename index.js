import 'dotenv/config';
import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import crypto from 'crypto'; // Module natif de Node.js pour la cryptographie
import bcrypt from 'bcrypt'; // Pour hacher les mots de passe
import jwt from 'jsonwebtoken'; // Pour les jetons de session (JWT)

// --- Imports LangChain (inchangés) ---
import { ChatHuggingFace } from '@langchain/huggingface';
import { ChatPromptTemplate } from '@langchain/core/prompts';
import { DuckDuckGoSearch } from '@langchain/community/tools/duckduckgo_search';
import { StringOutputParser } from '@langchain/core/output_parsers';
import { RunnablePassthrough } from '@langchain/core/runnables';

// === 1) Configuration et Initialisation ===
const PORT = 10000;
const llm = new ChatHuggingFace({ model: 'mistralai/Mixtral-8x7B-Instruct-v0.1', temperature: 0.7 });
const searchTool = new DuckDuckGoSearch({ maxResults: 5 });

// === 2) Fonctions pour la Base de Données (Mise à jour) ===
let dbConnection;
async function getDbConnection() {
  if (dbConnection) return dbConnection;
  dbConnection = await mysql.createConnection(process.env.DATABASE_URL);
  return dbConnection;
}

async function initDb() {
  const conn = await getDbConnection();
  // On crée la table 'users'
  await conn.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      api_token VARCHAR(255) UNIQUE
    )
  `);
  // On crée la table 'memory'
  await conn.execute(`
    CREATE TABLE IF NOT EXISTS memory (
      id INT AUTO_INCREMENT PRIMARY KEY,
      question TEXT NOT NULL,
      answer TEXT NOT NULL
    )
  `);
  console.log('Tables "users" et "memory" initialisées.');
}

// ... (fonctions searchMemory et addToMemory inchangées)

// === 3) Middlewares de Sécurité ===
// Middleware pour vérifier le jeton de session (JWT)
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1]; // Format: "Bearer VOTRE_TOKEN"
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403); // Forbidden
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401); // Unauthorized
  }
};

// Middleware pour vérifier la clé d'API permanente
const authenticateAPIKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ error: 'Clé API manquante dans le header X-API-Key' });
  }
  const conn = await getDbConnection();
  const [rows] = await conn.execute('SELECT id FROM users WHERE api_token = ?', [apiKey]);
  if (rows.length === 0) {
    return res.status(403).json({ error: 'Clé API invalide' });
  }
  next();
};

// === 4) Le Cerveau de l'IA (inchangé) ===
const generationChain = /* ... (la chaîne LangChain reste la même) ... */;
async function askAI(question) { /* ... (la fonction askAI reste la même) ... */ }

// === 5) Le Serveur Web avec les Nouvelles Routes ===
const app = express();
app.use(cors());
app.use(express.json());

// --- ROUTES PUBLIQUES (Authentification) ---
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Nom d'utilisateur et mot de passe requis" });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const conn = await getDbConnection();
    await conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashedPassword]);
    res.status(201).json({ message: "Utilisateur créé avec succès" });
  } catch (err) {
    res.status(500).json({ error: "Ce nom d'utilisateur est peut-être déjà pris" });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const conn = await getDbConnection();
  const [rows] = await conn.execute('SELECT * FROM users WHERE username = ?', [username]);
  if (rows.length === 0) return res.status(400).json({ error: "Identifiants invalides" });

  const user = rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(400).json({ error: "Identifiants invalides" });

  const accessToken = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ accessToken });
});

// --- ROUTE PROTÉGÉE (Génération de clé API - VOTRE CODE INTÉGRÉ ICI) ---
app.post("/user/api-token", authenticateJWT, async (req, res) => {
  try {
    const apiToken = "sk-" + crypto.randomBytes(24).toString("hex");
    const conn = await getDbConnection();
    // req.user est fourni par le middleware authenticateJWT
    await conn.execute("UPDATE users SET api_token=? WHERE id=?", [apiToken, req.user.id]);
    res.json({ api_token: apiToken });
  } catch (err) {
    res.status(500).json({ error: "Erreur lors de la génération de la clé API" });
  }
});

// --- ROUTE DE L'IA (Maintenant protégée par la clé API) ---
app.post('/ask', authenticateAPIKey, async (req, res) => {
  const { question } = req.body;
  if (!question) return res.status(400).json({ error: 'La question est manquante.' });
  try {
    const answer = await askAI(question);
    res.json({ answer: answer });
  } catch (error) {
    res.status(500).json({ error: "Une erreur interne est survenue." });
  }
});

// === 6) Démarrage du Serveur ===
async function startServer() {
  await initDb();
  app.listen(PORT, () => {
    console.log(`\n>>> Serveur Node.js avec authentification prêt ! Écoute sur le port ${PORT} <<<`);
  });
}

startServer();

// On doit remettre les fonctions LangChain ici pour que le code soit complet
const retriever = (query) => searchTool.invoke(query);
const promptTemplate = ChatPromptTemplate.fromTemplate(
  "En te basant sur ce contexte : {context}\n\nRéponds à cette question : {question}"
);
generationChain = RunnablePassthrough.assign({
  context: (input) => retriever(input.question),
}).pipe(promptTemplate).pipe(llm).pipe(new StringOutputParser());

async function askAI(question) {
    const cachedAnswer = await searchMemory(question);
    if (cachedAnswer) return `(Mémoire SQL) ${cachedAnswer}`;
    const newAnswer = await generationChain.invoke({ question });
    await addToMemory(question, newAnswer);
    return `(Recherche Web & IA) ${newAnswer}`;
}
