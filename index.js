import 'dotenv/config';
import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import fs from 'fs'; // --- NOUVEL IMPORT POUR LIRE LE FICHIER CERTIFICAT ---

// --- NOUVEL IMPORT HUGGING FACE ---
import { HfInference } from '@huggingface/inference';

// --- Imports LangChain (uniquement pour les outils) ---
import { DuckDuckGoSearch } from '@langchain/community/tools/duckduckgo_search';

// === 1) Configuration et Initialisation ===
const PORT = 10000;
// On initialise le client d'inférence de Hugging Face avec notre token
const hf = new HfInference(process.env.HUGGINGFACEHUB_API_TOKEN);
const searchTool = new DuckDuckGoSearch({ maxResults: 5 });

// ... (Fonctions de Sécurité restent identiques) ...
let dbConnection;
// --- FONCTION DE CONNEXION MODIFIÉE POUR UTILISER LE SSL ---
async function getDbConnection() {
  if (dbConnection) return dbConnection;

  // On lit le certificat SSL fourni par l'hébergeur de la base de données
  const ca = fs.readFileSync('cert/ca.pem', 'utf-8');

  // On se connecte en utilisant l'URL de la base de données ET le certificat
  dbConnection = await mysql.createConnection({
    uri: process.env.DATABASE_URL,
    ssl: {
      ca: ca
    }
  });

  return dbConnection;
}

async function initDb() { const conn = await getDbConnection(); await conn.execute(`CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, api_token VARCHAR(255) UNIQUE)`); await conn.execute(`CREATE TABLE IF NOT EXISTS memory (id INT AUTO_INCREMENT PRIMARY KEY, question TEXT NOT NULL, answer TEXT NOT NULL)`); console.log('Tables "users" et "memory" initialisées.'); }
async function searchMemory(question) { const conn = await getDbConnection(); const [rows] = await conn.execute('SELECT answer FROM memory WHERE question = ?', [question]); return rows.length > 0 ? rows[0].answer : null; }
async function addToMemory(question, answer) { const conn = await getDbConnection(); await conn.execute('INSERT INTO memory (question, answer) VALUES (?, ?)', [question, answer]); }
const authenticateJWT = (req, res, next) => { const authHeader = req.headers.authorization; if (authHeader) { const token = authHeader.split(' ')[1]; jwt.verify(token, process.env.JWT_SECRET, (err, user) => { if (err) return res.sendStatus(403); req.user = user; next(); }); } else { res.sendStatus(401); } };
const authenticateAPIKey = async (req, res, next) => { const apiKey = req.headers['x-api-key']; if (!apiKey) return res.status(401).json({ error: 'Clé API manquante dans le header X-API-Key' }); const conn = await getDbConnection(); const [rows] = await conn.execute('SELECT id FROM users WHERE api_token = ?', [apiKey]); if (rows.length === 0) return res.status(403).json({ error: 'Clé API invalide' }); next(); };

// === 4) Le Cerveau de l'IA (SIMPLIFIÉ SANS LANGCHAIN POUR LE LLM) ===
async function askAI(question) {
  // Étape 1 : Vérifier la mémoire cache SQL
  const cachedAnswer = await searchMemory(question);
  if (cachedAnswer) {
    return `(Mémoire SQL) ${cachedAnswer}`;
  }

  // Étape 2 : Chercher sur le web avec DuckDuckGo (on garde cet outil LangChain)
  const context = await searchTool.invoke(question);

  // Étape 3 : Construire le prompt et appeler l'API Hugging Face directement
  const prompt = `En te basant sur ce contexte : ${context}\n\nRéponds à cette question : ${question}`;
  
  const response = await hf.textGeneration({
    model: 'mistralai/Mixtral-8x7B-Instruct-v0.1',
    inputs: prompt,
    parameters: {
      max_new_tokens: 250,
      temperature: 0.7,
      return_full_text: false
    }
  });

  const newAnswer = response.generated_text.trim();

  // Étape 4 : Sauvegarder dans la mémoire et retourner la réponse
  await addToMemory(question, newAnswer);
  return `(Recherche Web & IA) ${newAnswer}`;
}

// === 5) Le Serveur Web avec les Routes (inchangé) ===
const app = express();
app.use(cors());
app.use(express.json());

// --- ROUTES PUBLIQUES (Authentification) ---
app.post('/register', async (req, res) => { const { username, password } = req.body; if (!username || !password) return res.status(400).json({ error: "Nom d'utilisateur et mot de passe requis" }); try { const hashedPassword = await bcrypt.hash(password, 10); const conn = await getDbConnection(); await conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashedPassword]); res.status(201).json({ message: "Utilisateur créé avec succès" }); } catch (err) { res.status(500).json({ error: "Ce nom d'utilisateur est peut-être déjà pris" }); } });
app.post('/login', async (req, res) => { const { username, password } = req.body; const conn = await getDbConnection(); const [rows] = await conn.execute('SELECT * FROM users WHERE username = ?', [username]); if (rows.length === 0) return res.status(400).json({ error: "Identifiants invalides" }); const user = rows[0]; const match = await bcrypt.compare(password, user.password_hash); if (!match) return res.status(400).json({ error: "Identifiants invalides" }); const accessToken = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' }); res.json({ accessToken }); });

// --- ROUTE PROTÉGÉE (Génération de clé API) ---
app.post("/user/api-token", authenticateJWT, async (req, res) => { try { const apiToken = "sk-" + crypto.randomBytes(24).toString("hex"); const conn = await getDbConnection(); await conn.execute("UPDATE users SET api_token=? WHERE id=?", [apiToken, req.user.id]); res.json({ api_token: apiToken }); } catch (err) { res.status(500).json({ error: "Erreur lors de la génération de la clé API" }); } });

// --- ROUTE DE L'IA (Protégée par la clé API) ---
app.post('/ask', authenticateAPIKey, async (req, res) => { const { question } = req.body; if (!question) return res.status(400).json({ error: 'La question est manquante.' }); try { const answer = await askAI(question); res.json({ answer: answer }); } catch (error) { console.error("Erreur critique:", error); res.status(500).json({ error: "Une erreur interne est survenue." }); } });

// === 6) Démarrage du Serveur ===
async function startServer() {
  try {
    await initDb();
    app.listen(PORT, () => {
      console.log(`\n>>> Serveur Node.js FINAL prêt ! Écoute sur le port ${PORT} <<<`);
    });
  } catch (error) {
    console.error("ERREUR FATALE AU DÉMARRAGE :", error);
    process.exit(1); // Arrête le processus si la connexion DB échoue
  }
}

startServer();
