// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import DOMPurify from "dompurify";

export function bad(comment) {
  const el = document.getElementById("c");
  const q = new URLSearchParams(location.search).get("q");
  // ruleid: shieldgate.js.xss-innerhtml
  el.innerHTML = "Results for " + q;
  // ruleid: shieldgate.js.xss-innerhtml
  document.write("<p>" + location.hash + "</p>");
  window.addEventListener("message", (e) => {
    // ruleid: shieldgate.js.xss-innerhtml
    el.innerHTML = e.data;
  });
  // ruleid: shieldgate.js.xss-dangerouslysetinnerhtml
  return <div dangerouslySetInnerHTML={{ __html: comment.body }} />;
}

export function good(comment) {
  const el = document.getElementById("c");
  // ok: shieldgate.js.xss-innerhtml
  el.textContent = comment.body;
  // ok: shieldgate.js.xss-innerhtml
  el.innerHTML = "<b>loading</b>";
  // ok: shieldgate.js.xss-innerhtml
  el.innerHTML = DOMPurify.sanitize(location.hash);
  // ok: shieldgate.js.xss-innerhtml
  el.innerHTML = renderTemplate(comment.body);
  // ok: shieldgate.js.xss-dangerouslysetinnerhtml
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />;
}
