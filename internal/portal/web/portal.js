// The portal is assumed hostile by its own threat model: a compromised addy
// serves this file. So it does as close to nothing as a page can, and nothing
// here ever touches a secret.
//
// In particular this file must never read location.hash. The one-time paste
// puts its decryption key in the fragment, the paste is same-origin with this
// page, and any script that reads the fragment -- or any XSS that can inject
// one -- reads the key of every paste opened in that browser.
(function () {
  fetch('/v1/meta', { credentials: 'omit' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (meta) {
      if (!meta) return;
      var el = document.getElementById('build');
      if (el) el.textContent = 'addy ' + meta.version + ' (' + meta.build + ')';
    })
    .catch(function () { /* the footer simply stays empty */ });
})();
