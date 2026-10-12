// Theme toggle. Light is the default; the head of each page applies a stored
// dark choice before first paint, and this script wires the header button.
(function () {
  var KEY = "layertree-theme";
  var root = document.documentElement;
  var button = document.querySelector(".theme-toggle");
  if (!button) return;

  function render() {
    var dark = root.getAttribute("data-theme") === "dark";
    button.setAttribute("aria-pressed", dark ? "true" : "false");
    button.textContent = dark ? "Light" : "Dark";
    button.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
  }

  button.addEventListener("click", function () {
    var dark = root.getAttribute("data-theme") !== "dark";
    if (dark) root.setAttribute("data-theme", "dark");
    else root.removeAttribute("data-theme");
    try { localStorage.setItem(KEY, dark ? "dark" : "light"); } catch (e) {}
    render();
  });

  render();
})();
