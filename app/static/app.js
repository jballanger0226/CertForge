/* Small progressive enhancements. Every page works without this file. */
(function () {
  "use strict";

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    // Fallback for pages loaded over HTTPS with an unaccepted-but-bypassed certificate
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy") ? resolve() : reject(); } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }

  // Alphabet without look-alikes (no 0/O, 1/I/l). 31 symbols; reject bytes >= 248 so each is equally likely.
  var ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  function randomPassphrase(groups, size) {
    var out = [];
    for (var g = 0; g < groups; g++) {
      var part = "";
      while (part.length < size) {
        var buf = new Uint8Array(16);
        crypto.getRandomValues(buf);
        for (var i = 0; i < buf.length && part.length < size; i++) {
          if (buf[i] < 248) part += ALPHABET[buf[i] % ALPHABET.length];
        }
      }
      out.push(part);
    }
    return out.join("-");
  }

  document.addEventListener("click", function (e) {
    var copy = e.target.closest("[data-copy]");
    if (copy) {
      var src = document.querySelector(copy.getAttribute("data-copy"));
      if (src) {
        var label = copy.textContent;
        copyText(src.textContent.trim()).then(function () {
          copy.textContent = "Copied";
          setTimeout(function () { copy.textContent = label; }, 1600);
        }, function () {
          copy.textContent = "Press Ctrl+C";
          var r = document.createRange(); r.selectNodeContents(src);
          var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        });
      }
      return;
    }
    var gen = e.target.closest("[data-generate]");
    if (gen) {
      var input = document.querySelector(gen.getAttribute("data-generate"));
      if (input) {
        input.type = "text";
        input.value = randomPassphrase(4, 5);
        input.focus();
        input.select();
      }
    }
  });

  // Stop double-submits on slow actions (key generation can take a few seconds)
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var busy = form.getAttribute("data-busy");
    if (!busy) return;
    var btn = form.querySelector("button[type=submit], button:not([type])");
    if (btn) {
      setTimeout(function () { btn.disabled = true; btn.textContent = busy; }, 0);
    }
  });

  // Trust page: open the instructions for the device you're on
  var ua = navigator.userAgent || "";
  var os = /iPhone|iPad|iPod/.test(ua) ? "ios"
    : /Android/.test(ua) ? "android"
    : /Windows/.test(ua) ? "windows"
    : /Macintosh|Mac OS X/.test(ua) ? "mac"
    : /Linux|X11/.test(ua) ? "linux" : "";
  if (os) {
    var mine = document.querySelector('details.os[data-os="' + os + '"]');
    if (mine) { mine.open = true; mine.classList.add("yours"); }
  }
})();
