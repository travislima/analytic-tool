/* plainsight tracker — no cookies, no localStorage IDs, no fingerprinting.
   Sends: site id, path, referrer, viewport width, timezone (for country). */
(function () {
  var s = document.currentScript;
  if (!s) return;
  var site = s.getAttribute("data-site");
  if (!site) return;
  var api = s.getAttribute("data-api") || s.src.replace(/\/a\.js(\?.*)?$/, "/api/event");
  var last;

  function send() {
    if (/^localhost$|^127\./.test(location.hostname) && !s.getAttribute("data-dev")) return;
    var p = location.pathname;
    if (p === last) return;
    last = p;
    var tz = "";
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) {}
    var r = document.referrer || "";
    try { if (r && new URL(r).host === location.host) r = ""; } catch (e) {}
    var body = JSON.stringify({ s: site, p: p, r: r, w: innerWidth, tz: tz });
    if (navigator.sendBeacon) navigator.sendBeacon(api, body);
    else {
      var x = new XMLHttpRequest();
      x.open("POST", api, true);
      x.send(body);
    }
  }

  /* count SPA navigations too */
  var h = history, push = h.pushState;
  if (push) {
    h.pushState = function () { push.apply(h, arguments); send(); };
    addEventListener("popstate", send);
  }

  if (document.visibilityState === "hidden" || document.visibilityState === "prerender") {
    document.addEventListener("visibilitychange", function onv() {
      if (!last && document.visibilityState === "visible") { document.removeEventListener("visibilitychange", onv); send(); }
    });
  } else {
    send();
  }
})();
