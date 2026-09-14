'use strict';

(() => {
  const button = document.querySelector('#installApp');
  const notice = document.querySelector('#connectivityNotice');
  let installPrompt = null;
  const installed = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  function updateInstall() { button.hidden = installed(); }
  function updateConnection() {
    notice.hidden = navigator.onLine !== false;
    setBusy(busy);
  }
  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault();
    installPrompt = event;
    updateInstall();
  });
  window.addEventListener('appinstalled', () => { installPrompt = null; button.hidden = true; toast('SKALA installed.'); });
  button.addEventListener('click', async () => {
    if (!['http:','https:'].includes(location.protocol)) {
      toast('Open the hosted SKALA address to install the app.');
      return;
    }
    if (!installPrompt) {
      openDetail('install',button);
      return;
    }
    const prompt = installPrompt;
    installPrompt = null;
    try { await prompt.prompt(); await prompt.userChoice; }
    catch { openDetail('install',button); }
  });
  window.addEventListener('online',updateConnection);
  window.addEventListener('offline',updateConnection);
  updateInstall();
  updateConnection();
  if ('serviceWorker' in navigator && ['http:','https:'].includes(location.protocol)) {
    navigator.serviceWorker.register('/sw.js',{scope:'/',updateViaCache:'none'})
      .catch(() => { button.title = 'Install from the browser menu. Offline support is unavailable in this session.'; });
  }
})();
