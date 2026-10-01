const express = require('express');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const helmet = require('helmet'); 
const rateLimit = require('express-rate-limit'); 

const app = express();

app.use(helmet()); 
app.use(express.json({ limit: '10kb' })); 
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 30, 
  message: { error: 'Muitas requisições originadas deste IP. Tente novamente mais tarde.' }
});

const users = new Map(); 
const credentials = new Map();

const rpName = 'Midas Touch - Aprovação Financeira';
const rpID = process.env.RENDER_EXTERNAL_HOSTNAME || 'localhost'; 
const origin = rpID === 'localhost' ? `http://${rpID}:3000` : `https://${rpID}`; 

app.post('/api/register/generate', apiLimiter, async (req, res) => {
  try {
    let { username } = req.body;
    if (!username || typeof username !== 'string' || username.length > 100) {
      return res.status(400).json({ error: 'Payload de entrada inválido.' });
    }
    username = username.trim().toLowerCase();

    let user = Array.from(users.values()).find(u => u.username === username);
    if (!user) {
      const newId = crypto.randomBytes(16).toString('base64url');
      user = { id: newId, username };
      users.set(newId, user);
      credentials.set(newId, []);
    }

    const userCredentials = credentials.get(user.id);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: new Uint8Array(Buffer.from(user.id)),
      userName: user.username,
      attestationType: 'none',
      excludeCredentials: userCredentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred',
      },
    });

    user.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('[FATAL] Erro na geração de registro:', error.message);
    res.status(500).json({ error: 'Erro interno ao processar a geração de credenciais.' });
  }
});

app.post('/api/register/verify', apiLimiter, async (req, res) => {
  try {
    let { username, response } = req.body;
    if (!username || typeof username !== 'string' || !response) {
      return res.status(400).json({ error: 'Payload inválido ou incompleto.' });
    }
    username = username.trim().toLowerCase();

    const user = Array.from(users.values()).find(u => u.username === username);
    if (!user || !user.currentChallenge) {
      return res.status(400).json({ error: 'Ciclo de registro inválido ou expirado.' });
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;

      credentials.get(user.id).push({
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports,
      });

      user.currentChallenge = null;
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'A validação criptográfica foi rejeitada pelo servidor.' });
    }
  } catch (error) {
    console.error('[FATAL] Erro na verificação do registro:', error.message);
    res.status(400).json({ error: 'Falha durante o processo de verificação biométrica.' });
  }
});

app.post('/api/authenticate/generate', apiLimiter, async (req, res) => {
  try {
    let { username } = req.body;
    if (!username || typeof username !== 'string') {
      return res.status(400).json({ error: 'Payload inválido.' });
    }
    username = username.trim().toLowerCase();

    const user = Array.from(users.values()).find(u => u.username === username);

    if (!user) {
      return res.status(400).json({ error: 'Processo não pôde ser iniciado. Verifique suas credenciais.' });
    }

    const userCredentials = credentials.get(user.id) || [];
    
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: userCredentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      })),
      userVerification: 'preferred',
    });

    user.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('[FATAL] Erro na geração de autenticação:', error.message);
    res.status(500).json({ error: 'Erro de processamento interno.' });
  }
});

app.post('/api/authenticate/verify', apiLimiter, async (req, res) => {
  try {
    let { username, response } = req.body;
    if (!username || typeof username !== 'string' || !response) {
      return res.status(400).json({ error: 'Payload malformado.' });
    }
    username = username.trim().toLowerCase();

    const user = Array.from(users.values()).find(u => u.username === username);

    if (!user || !user.currentChallenge) {
      return res.status(400).json({ error: 'Sessão inválida. O desafio pode ter expirado ou foi sobrescrito.' });
    }

    const userCredentials = credentials.get(user.id) || [];
    const credential = userCredentials.find(c => c.id === response.id);

    if (!credential) {
      return res.status(400).json({ error: 'Credencial biométrica fornecida não está atrelada ao usuário.' });
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports,
      }
    });

    if (verification.verified) {
      credential.counter = verification.authenticationInfo.newCounter;
      user.currentChallenge = null;
      res.json({ verified: true, message: 'Transferência validada matematicamente.' });
    } else {
      res.status(400).json({ error: 'Inconsistência criptográfica detectada. Assinatura falhou.' });
    }
  } catch (error) {
    console.error('[FATAL] Erro na verificação da autenticação:', error.message);
    res.status(400).json({ error: 'Falha fatal na assinatura digital.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 [SECURE] Portal "Toque de Midas" (QA Audited) rodando na porta ${PORT}`);
});
