/// <reference types="vite/client" />
import "altcha/external";
import "altcha/altcha.css";
import "altcha/i18n/zh-cn";
import { State } from "altcha/types";
import PBKDF2Worker from "altcha/workers/pbkdf2?worker";
import "./challenge.css";

globalThis.$altcha.algorithms.set("PBKDF2/SHA-256", () => new PBKDF2Worker());

async function initialize() {
  const root = document.getElementById("challenge")!;
  const status = document.getElementById("status")!;
  const retry = document.getElementById("retry") as HTMLButtonElement;
  const ticket = root.dataset.ticket!;
  const widget = document.createElement("altcha-widget");
  let redeeming = false;
  widget.addEventListener("verified", (event) => {
    if (redeeming) return;
    redeeming = true;
    status.textContent = "正在确认验证结果。";
    const { payload } = (event as CustomEvent<{ payload: string }>).detail;
    void (async () => {
      try {
        // A widget's verified event only proves local computation completed.
        // Only the WAF may grant clearance or authorize a return navigation.
        const response = await fetch("/.waf/challenge/solve", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ticket, payload }),
        });
        const result = await response.json();
        if (!response.ok || !result.cleared)
          throw new Error("verification failed");
        retry.hidden = true;
        status.textContent = result.redirect
          ? "验证成功，正在返回页面。"
          : "验证成功，请返回应用重试原请求。";
        if (result.redirect) location.replace(result.redirect);
      } catch {
        redeeming = false;
        widget.setState(State.ERROR, "验证失败或已过期，请返回原页面重试。");
      }
    })();
  });
  widget.addEventListener("statechange", (event) => {
    const { state } = (event as CustomEvent<{ state: string }>).detail;
    if (state === "error" || state === "expired") {
      status.textContent = "验证失败或已过期，请返回原页面重试。";
      retry.hidden = false;
    }
  });
  retry.addEventListener("click", () => {
    // Refresh the original navigation to obtain a newly selected mode and ticket.
    // API verification pages must be reopened using a fresh challenge_url.
    if (location.pathname !== "/.waf/challenge") location.reload();
    else status.textContent = "请返回应用重试请求，获取新的验证链接。";
  });
  document.getElementById("widget")!.append(widget);
  // ALTCHA's custom element exposes its methods after the connected microtask.
  await Promise.resolve();
  await widget.configure({
    challenge: "/.waf/challenge/puzzle?ticket=" + encodeURIComponent(ticket),
    auto: root.dataset.mode === "interactive" ? "off" : "onload",
    language: "zh-cn",
    credentials: "same-origin",
    humanInteractionSignature: false,
    workers: Math.min(4, navigator.hardwareConcurrency || 2),
  });
}
void initialize().catch(() => {
  document.getElementById("status")!.textContent =
    "浏览器无法完成验证，请联系网站管理员。";
});
