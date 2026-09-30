# 🥇 Toque de Midas (Midas Touch)

Uma aplicação Web de Segurança Financeira criada para aprovação de transferências bancárias de altíssimo valor utilizando biometria nativa do dispositivo (WebAuthn / FIDO2).

Projeto desenvolvido pela **Equipe 2** para demonstrar segurança criptográfica avançada e aderência à LGPD em fluxos de validação de diretores/CEOs de Fintechs.

## 🚀 Tecnologias Utilizadas
* **Backend:** Node.js, Express
* **Criptografia e FIDO2:** `@simplewebauthn/server` e `@simplewebauthn/browser`
* **Frontend:** HTML5, JavaScript (Vanilla) e Tailwind CSS
* **Banco de Dados:** Em Memória (JS Objects) para fins de MVP/Pitch.

## 🔐 Como funciona a Segurança (LGPD)
Este projeto **não salva a impressão digital do usuário no servidor**. 
O sistema utiliza criptografia assimétrica da `WebAuthn API`:
1. O dispositivo do usuário gera um par de chaves usando o hardware seguro (TPM/Secure Enclave).
2. A chave **Privada** fica trancada no aparelho do usuário (desbloqueada só pela digital).
3. A chave **Pública** é enviada e armazenada em nosso Banco de Dados.
4. Para aprovar uma transferência, o servidor emite um desafio e o celular assina matematicamente usando a digital. O servidor só valida a assinatura. Se houver vazamento de DB, hackers só encontrarão chaves públicas inofensivas.

## 💻 Como Rodar o Projeto
1. Certifique-se de ter o Node.js instalado.
2. Clone o repositório ou baixe os arquivos.
3. Abra o terminal na pasta do projeto e instale as dependências:
   ```bash
   npm install
   ```
4. Inicie o servidor:
   ```bash
   node server.js
   ```
5. Acesse `http://localhost:3000` no navegador.

> **Importante:** A tecnologia WebAuthn exige que o acesso seja feito através de `localhost` ou domínios com certificado `HTTPS`. Se for rodar no celular localmente, utilize o software `ngrok`.
