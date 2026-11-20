/* Landing page: one scripted moment. The example email is "scanned" once and the highlights appear behind the scan line. */
(function () {
  "use strict";
  const xray = document.getElementById("xray");
  if (!xray) return;
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) return;                      // highlights stay visible, no animation
  xray.classList.remove("revealed");
  requestAnimationFrame(() => requestAnimationFrame(() => {
    xray.classList.add("scanning");
    setTimeout(() => xray.classList.add("revealed"), 1100);       // highlights appear as the line passes them
    setTimeout(() => xray.classList.remove("scanning"), 1900);
  }));
})();
