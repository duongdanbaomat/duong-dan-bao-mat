import { apiVersions } from "./api.js";
import { decode, base64ToBinary } from "./b64.js";

function main() {
  const hash = window.location.hash.slice(1);
  const params = JSON.parse(decode(hash));
  const api = apiVersions[params.v];

  const encrypted = base64ToBinary(params.e);
  const salt = params.s ? base64ToBinary(params.s) : null;
  const iv = params.i ? base64ToBinary(params.i) : null;

  const form = document.querySelector("#password-form");
  const passwordPrompt = form.querySelector("#password");
  const unlockButton = form.querySelector("button[type='submit']");

  passwordPrompt.addEventListener("input", async () => {
    const password = passwordPrompt.value;
    if (!password) {
      unlockButton.disabled = true;
      return;
    }

    try {
      await api.decrypt(encrypted, password, salt, iv);
      unlockButton.disabled = false;
    } catch {
      unlockButton.disabled = true;
    }
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = passwordPrompt.value;
    const url = await api.decrypt(encrypted, password, salt, iv);
    window.location.href = url;
  });
}

document.addEventListener("DOMContentLoaded", main);
