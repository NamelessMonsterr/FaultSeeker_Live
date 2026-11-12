/* Sign-in page. External script only (the CSP forbids inline scripts). */
(() => {
  'use strict';
  const form = document.getElementById('login-form');
  const input = document.getElementById('code');
  const error = document.getElementById('login-error');
  const button = document.getElementById('login-submit');

  function fail(message) {
    error.textContent = message;
    error.hidden = false;
    input.setAttribute('aria-invalid', 'true');
    input.focus();
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.hidden = true;
    input.removeAttribute('aria-invalid');
    button.disabled = true;
    try {
      const res = await fetch('/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store',
        body: JSON.stringify({ code: input.value }),
      });
      if (res.ok) { window.location.assign('/'); return; }
      let message = 'Sign-in failed. Try again.';
      try { message = (await res.json()).error.message || message; } catch (_) { /* keep default */ }
      fail(message);
    } catch (_) {
      fail('Could not reach the server. Check your connection and try again.');
    } finally {
      button.disabled = false;
      input.value = '';
    }
  });
  input.focus();
})();
