// Detail side panel for the Case workspace. Loaded as a same-origin file so the
// Content-Security-Policy (no inline script) stays unchanged. Without
// JavaScript every ID link still works as a normal link.
(function () {
  "use strict";

  function panel() {
    return document.getElementById("detail-panel");
  }

  function open(url, link) {
    var target = panel();
    if (!target) {
      return false;
    }
    target.setAttribute("aria-busy", "true");
    fetch(url, { headers: { "X-Requested-With": "fetch" }, credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) {
          throw new Error(String(response.status));
        }
        return response.text();
      })
      .then(function (html) {
        // The fragment is rendered by the server with autoescaping.
        target.innerHTML = html;
        target.hidden = false;
        target.removeAttribute("aria-busy");
        document.querySelectorAll("a.id.active").forEach(function (a) {
          a.classList.remove("active");
        });
        if (link) {
          link.classList.add("active");
        }
        var heading = target.querySelector("h3");
        if (heading) {
          heading.setAttribute("tabindex", "-1");
          heading.focus({ preventScroll: true });
        }
      })
      .catch(function () {
        target.removeAttribute("aria-busy");
        target.textContent = "상세 정보를 불러오지 못했습니다.";
        target.hidden = false;
      });
    return true;
  }

  document.addEventListener("click", function (event) {
    var link = event.target.closest("a[data-detail]");
    if (link && !event.ctrlKey && !event.metaKey && !event.shiftKey) {
      if (open(link.getAttribute("data-detail"), link)) {
        event.preventDefault();
      }
      return;
    }
    var close = event.target.closest("[data-close-detail]");
    if (close && panel()) {
      panel().hidden = true;
    }
    var toggle = event.target.closest("[data-lang]");
    if (toggle) {
      var scope = document.getElementById(toggle.getAttribute("data-scope"));
      if (scope) {
        scope.setAttribute("data-show", toggle.getAttribute("data-lang"));
        scope.querySelectorAll("[data-lang]").forEach(function (b) {
          b.setAttribute("aria-pressed", String(b === toggle));
        });
      }
    }
  });

  document.addEventListener("keydown", function (event) {
    var field = document.querySelector(".search input");
    if (event.key === "/" && field && document.activeElement.tagName !== "INPUT" &&
        document.activeElement.tagName !== "TEXTAREA") {
      event.preventDefault();
      field.focus();
    }
    if (event.key === "Escape" && panel()) {
      panel().hidden = true;
    }
  });
})();
