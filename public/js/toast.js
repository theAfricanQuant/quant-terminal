export function setToastContent(element, content, { trustedHtml = false } = {}) {
  if (trustedHtml) element.innerHTML = String(content ?? "");
  else element.textContent = String(content ?? "");
}
