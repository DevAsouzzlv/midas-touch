const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

// Referências da DOM
const sectionRegister = document.getElementById('section-register');
const sectionTransfer = document.getElementById('section-transfer');
const usernameInput = document.getElementById('username');
const btnRegister = document.getElementById('btn-register');
const btnApprove = document.getElementById('btn-approve');
const btnLogout = document.getElementById('btn-logout');
const displayUser = document.getElementById('display-user');

let currentUser = '';

let isProcessing = false;

// ==========================================
// 1. REGISTRAR BIOMETRIA
// ==========================================
btnRegister.addEventListener('click', async () => {
  if (isProcessing) return;
  
  const username = usernameInput.value.trim();
  if (!username) {
    alert('Por favor, digite um e-mail corporativo válido.');
    return;
  }

  isProcessing = true;
  btnRegister.style.opacity = '0.7';
  btnRegister.style.cursor = 'not-allowed';
  const originalText = btnRegister.innerHTML;
  btnRegister.innerHTML = '<i class="ph ph-spinner animate-spin text-2xl text-midas-400"></i> Aguardando Sensor...';

  try {
    // 1.1 Pedir opções de registro para o servidor
    const resp = await fetch('/api/register/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });

    if (!resp.ok) throw new Error(await resp.text());
    const options = await resp.json();

    // 1.2 Chamar a API Nativa do SO (Touch ID, Windows Hello, etc)
    let attestationResponse;
    try {
      attestationResponse = await startRegistration({ optionsJSON: options });
    } catch (error) {
      if (error.name === 'InvalidStateError') {
        alert('Atenção: Este dispositivo/biometria já está cadastrado para este usuário.');
        showTransferScreen(username);
      } else {
        throw error;
      }
      return;
    }

    // 1.3 Enviar a Chave Pública e Assinatura para o Backend validar
    const verificationResp = await fetch('/api/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        response: attestationResponse,
      }),
    });

    const verificationJSON = await verificationResp.json();

    if (verificationJSON && verificationJSON.verified) {
      alert('✅ Dispositivo vinculado com sucesso!');
      showTransferScreen(username);
    } else {
      alert('❌ Erro: Não foi possível vincular a biometria.\n' + (verificationJSON.error || ''));
    }
  } catch (error) {
    console.error(error);
    alert('Ocorreu um erro no cadastro: ' + error.message);
  } finally {
    isProcessing = false;
    btnRegister.style.opacity = '1';
    btnRegister.style.cursor = 'pointer';
    btnRegister.innerHTML = originalText;
  }
});


// ==========================================
// 2. APROVAR TRANSFERÊNCIA (Autenticação)
// ==========================================
btnApprove.addEventListener('click', async () => {
  if (!currentUser || isProcessing) return;

  isProcessing = true;
  btnApprove.style.opacity = '0.7';
  btnApprove.style.cursor = 'not-allowed';
  const originalText = btnApprove.innerHTML;
  btnApprove.innerHTML = '<i class="ph ph-spinner animate-spin text-2xl drop-shadow-md"></i> Verificando...';

  try {
    // 2.1 Pedir o Desafio (Challenge) para o servidor
    const resp = await fetch('/api/authenticate/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: currentUser }),
    });

    if (!resp.ok) throw new Error(await resp.text());
    const options = await resp.json();

    // 2.2 Chamar a biometria para assinar o desafio
    let assertionResponse;
    try {
      assertionResponse = await startAuthentication({ optionsJSON: options });
    } catch (error) {
      console.error(error);
      alert('Operação cancelada ou biometria falhou.');
      return;
    }

    // 2.3 Enviar assinatura para o backend validar matematicamente
    const verificationResp = await fetch('/api/authenticate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: currentUser,
        response: assertionResponse,
      }),
    });

    const verificationJSON = await verificationResp.json();

    if (verificationJSON && verificationJSON.verified) {
      alert('🎉 SUCESSO!\n\nA assinatura criptográfica é válida.\nTransferência de R$ 1.500.000,00 aprovada.');
    } else {
      alert('❌ TRANSFERÊNCIA NEGADA.\nAssinatura biométrica inválida.');
    }
  } catch (error) {
    console.error(error);
    alert('Erro na aprovação: ' + error.message);
  } finally {
    isProcessing = false;
    btnApprove.style.opacity = '1';
    btnApprove.style.cursor = 'pointer';
    btnApprove.innerHTML = originalText;
  }
});


// ==========================================
// UTILITÁRIOS DA UI
// ==========================================
function showTransferScreen(username) {
  currentUser = username;
  displayUser.textContent = `Logado como: ${username}`;
  sectionRegister.classList.add('hidden');
  sectionTransfer.classList.remove('hidden');
}

btnLogout.addEventListener('click', () => {
  currentUser = '';
  usernameInput.value = '';
  sectionTransfer.classList.add('hidden');
  sectionRegister.classList.remove('hidden');
});
