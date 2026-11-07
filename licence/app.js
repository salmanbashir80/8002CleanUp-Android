import { unlockOwnerKey, issueLicence, verifyLicence } from './licence-crypto.mjs';
const byId = id => document.getElementById(id);
let signingKey = null, idleTimer = null, currentLicence = null;
function feedback(id, message, error = false) { const node = byId(id); node.textContent = message; node.classList.toggle('error', error); }
function clearResult() { currentLicence = null; byId('activation-key').value = ''; byId('licence-summary').textContent = ''; byId('result-panel').hidden = true; feedback('copy-message', ''); }
function lock() {
  signingKey = null; clearTimeout(idleTimer); clearResult(); byId('licence-fields').disabled = true;
  byId('unlock-form').hidden = false; byId('lock').hidden = true; byId('unlock-code').value = '';
  byId('lock-state').textContent = 'Locked'; byId('lock-state').classList.remove('active');
  feedback('unlock-message', 'Generator locked. Paste your owner unlock code to continue.'); feedback('generation-message', '');
}
function touch() { if (signingKey) { clearTimeout(idleTimer); idleTimer = setTimeout(lock, 10 * 60000); } }
document.addEventListener('pointerdown', touch); document.addEventListener('keydown', touch);
byId('lock').addEventListener('click', lock);
byId('unlock-form').addEventListener('submit', async event => {
  event.preventDefault(); const button = byId('unlock'); button.disabled = true; button.textContent = 'Unlocking…';
  feedback('unlock-message', 'Checking the encrypted signing key…');
  try {
    if (!crypto.subtle) throw Error('Use Chrome and open the https:// version of this page.');
    const response = await fetch('./owner-key.enc.json', { cache: 'no-store', credentials: 'omit', redirect: 'error' });
    if (!response.ok) throw Error('Encrypted key backup could not load. Refresh this page and try again.');
    signingKey = await unlockOwnerKey(await response.json(), byId('unlock-code').value);
    byId('unlock-code').value = ''; byId('unlock-form').hidden = true; byId('lock').hidden = false;
    byId('licence-fields').disabled = false; byId('lock-state').textContent = 'Unlocked'; byId('lock-state').classList.add('active');
    feedback('unlock-message', 'Ready. Paste the device code from the Android app below.'); touch(); byId('customer').focus();
  } catch (error) { byId('unlock-code').value = ''; feedback('unlock-message', error.message, true); }
  finally { button.disabled = false; button.textContent = 'Unlock generator'; }
});
byId('unbound').addEventListener('change', event => {
  const unbound = event.target.checked; byId('device').disabled = unbound; byId('device').required = !unbound;
});
byId('licence-form').addEventListener('submit', async event => {
  event.preventDefault(); clearResult(); const button = byId('generate'); button.disabled = true;
  try {
    if (!signingKey) throw Error('Unlock owner access first.');
    const result = await issueLicence(signingKey, { name: byId('customer').value, device: byId('unbound').checked ? '*' : byId('device').value, days: byId('days').value, allowUnbound: byId('unbound').checked });
    if (!await verifyLicence(result.token)) throw Error('Generated signature did not verify. Please reload the tool.');
    if (!signingKey) throw Error('The tool locked. Unlock it and generate the licence again.');
    currentLicence = result; byId('activation-key').value = result.token;
    byId('licence-summary').textContent = result.payload.name + ' · ' + (result.payload.device === '*' ? 'Any device' : result.payload.device) + ' · ' + (result.payload.expiresAt ? 'Expires ' + new Date(result.payload.expiresAt).toLocaleDateString() : 'Lifetime');
    byId('result-panel').hidden = false; feedback('generation-message', 'Signature verified. Your Pro activation key is ready.'); touch(); byId('result-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { feedback('generation-message', error.message, true); }
  finally { button.disabled = false; }
});
byId('copy').addEventListener('click', async () => {
  if (!currentLicence) return;
  try { await navigator.clipboard.writeText(currentLicence.token); feedback('copy-message', 'Copied. Paste into Settings → Licence & trial → Activate licence.'); }
  catch { byId('activation-key').focus(); byId('activation-key').select(); byId('activation-key').setSelectionRange(0, byId('activation-key').value.length); feedback('copy-message', 'The key is selected. Use your phone’s Copy command.'); }
});
byId('download').addEventListener('click', () => {
  if (!currentLicence) return;
  const url = URL.createObjectURL(new Blob([currentLicence.token + '\n'], { type: 'text/plain;charset=utf-8' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = '8002CleanUp-Pro-Licence.txt'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
if (!crypto.subtle) { feedback('unlock-message', 'Open this page in Chrome using its https:// address.', true); byId('unlock').disabled = true; }
