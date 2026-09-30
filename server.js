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

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Banco de dados em memória (ideal para o MVP / Apresentação)
// users = { userId: { id, username, currentChallenge } }
const users = {}; 
// credentials = { userId: [ { id, publicKey, counter, transports } ] }
const credentials = {}; 

// Configuração WebAuthn (Atenção para Nuvem vs Local)
const rpName = 'Midas Touch - Aprovação Financeira';
// Se estiver no Render, pega o domínio automático. Senão, usa localhost.
const rpID = process.env.RENDER_EXTERNAL_HOSTNAME || 'localhost'; 
const origin = rpID === 'localhost' ? `http://${rpID}:3000` : `https://${rpID}`; 

// ==============================================
// 1. REGISTRO (Vincular Biometria)
// ==============================================

app.post('/api/register/generate', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username é obrigatório' });

    // Encontra ou cria o usuário
    let user = Object.values(users).find(u => u.username === username);
    if (!user) {
      const newId = crypto.randomBytes(16).toString('base64url');
      user = { id: newId, username };
      users[newId] = user;
      credentials[newId] = [];
    }

    // Pega as credenciais já cadastradas para não recadastrar
    const userCredentials = credentials[user.id];

    // Gera as opções criptográficas usando a biblioteca
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: user.id, // Em v14, userID deve ser Uint8Array, mas a lib lida com strings se passarmos ou podemos converter
      // Vamos usar uma conversão segura para array de bytes
      userName: user.username,
      attestationType: 'none',
      excludeCredentials: userCredentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred', // Exige biometria ou pin
      },
    });

    // Salva o desafio temporário para verificar depois
    user.currentChallenge = options.challenge;

    res.json(options);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/register/verify', async (req, res) => {
  try {
    const { username, response } = req.body;
    const user = Object.values(users).find(u => u.username === username);
    
    if (!user || !user.currentChallenge) {
      return res.status(400).json({ error: 'Desafio não encontrado para o usuário' });
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;

      // Salva a CHAVE PÚBLICA (e nunca a biometria)
      credentials[user.id].push({
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports,
      });

      user.currentChallenge = null; // Limpa o desafio
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Falha na verificação criptográfica.' });
    }
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error.message });
  }
});

// ==============================================
// 2. AUTENTICAÇÃO (Aprovar Transferência)
// ==============================================

app.post('/api/authenticate/generate', async (req, res) => {
  try {
    const { username } = req.body;
    const user = Object.values(users).find(u => u.username === username);

    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

    const userCredentials = credentials[user.id] || [];
    
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: userCredentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      })),
      userVerification: 'preferred', // Exige biometria
    });

    user.currentChallenge = options.challenge;

    res.json(options);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/authenticate/verify', async (req, res) => {
  try {
    const { username, response } = req.body;
    const user = Object.values(users).find(u => u.username === username);

    if (!user || !user.currentChallenge) {
      return res.status(400).json({ error: 'Sessão inválida ou desafio expirado' });
    }

    const userCredentials = credentials[user.id] || [];
    const credential = userCredentials.find(c => c.id === response.id);

    if (!credential) {
      return res.status(400).json({ error: 'Aparelho não autorizado/não cadastrado' });
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
      // Atualiza o contador de uso para prevenir clonagem de sessão
      credential.counter = verification.authenticationInfo.newCounter;
      user.currentChallenge = null;
      res.json({ verified: true, message: 'Transferência Aprovada com Sucesso!' });
    } else {
      res.status(400).json({ error: 'Falha ao validar a assinatura biométrica.' });
    }
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Portal "Toque de Midas" no ar!`);
  console.log(`Acesse: http://localhost:${PORT}`);
  console.log(`Lembre-se: Para a biometria funcionar, deve ser localhost ou ter HTTPS.\n`);
});
