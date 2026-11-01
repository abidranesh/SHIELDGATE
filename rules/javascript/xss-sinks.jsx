// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import DOMPurify from "dompurify";

export function bad(comment) {
  const el = document.getElementById("c");
  // ruleid: shieldgate.js.xss-innerhtml
  el.innerHTML = comment.body;
  // ruleid: shieldgate.js.xss-innerhtml
  document.write("<p>" + location.hash + "</p>");
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
  el.innerHTML = DOMPurify.sanitize(comment.body);
  // ok: shieldgate.js.xss-dangerouslysetinnerhtml
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />;
}
