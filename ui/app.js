const state = {
  bridgeReady: false,
  encryptMode: "password",
  recipientKeys: [],
};

const pageMeta = {
  dashboard: ["Dashboard", "Overview of the current workspace."],
  encrypt: ["Encrypt", "Protect a local file."],
  decrypt: ["Decrypt", "Recover a verified plaintext file."],
  identity: ["Identities", "Create encryption and signing identities."],
  contacts: ["Contacts", "Manage local trust decisions for public identities."],
  inspect: ["Inspect & Verify", "Read and authenticate AegisCrypt capsules."],
  attack: ["Attack Lab", "Run controlled tamper tests."],
  planner: ["Policy Planner", "Map requirements to available protection."],
};

const $ = (id) => document.getElementById(id);

function toast(message, error = false) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("error", error);
  el.classList.add("show");
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
}

function setBridgeStatus(ready) {
  state.bridgeReady = ready;
  $("previewBanner").classList.toggle("hidden", ready);
}

function showPage(page) {
  document.querySelectorAll(".page").forEach((el) => el.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach((el) => el.classList.remove("active"));
  $(`page-${page}`).classList.add("active");

  const nav = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (nav) nav.classList.add("active");

  $("pageTitle").textContent = pageMeta[page][0];
  $("pageSubtitle").textContent = pageMeta[page][1];
}

async function bridgeCall(method, ...args) {
  if (!state.bridgeReady || !window.pywebview?.api?.[method]) {
    throw new Error("Desktop mode is not active. Run python desktop.py.");
  }

  const result = await window.pywebview.api[method](...args);

  if (!result?.ok) {
    throw new Error(result?.error || "Operation failed.");
  }

  return result;
}

async function chooseSingle(targetId) {
  const result = await bridgeCall("pick_file");
  if (result.path) {
    $(targetId).value = result.path;
  }
}

function clearSecretFields(...ids) {
  ids.forEach((id) => {
    if ($(id)) $(id).value = "";
  });
}

function pretty(data) {
  return JSON.stringify(data, null, 2);
}

function scorePassword(value) {
  let score = 0;
  if (value.length >= 10) score++;
  if (value.length >= 14) score++;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score++;
  if (/\d/.test(value)) score++;
  if (/[^A-Za-z0-9]/.test(value)) score++;
  return Math.min(score, 5);
}

function updateStrength() {
  const value = $("encryptPassword").value;
  const score = scorePassword(value);
  const pct = score * 20;
  const labels = ["Enter a password", "Very weak", "Weak", "Fair", "Good", "Strong"];

  $("strengthFill").style.width = `${pct}%`;
  $("strengthText").textContent = labels[score];

  const colors = ["#d46a6a", "#d46a6a", "#d6a24a", "#d6a24a", "#55b88a", "#55b88a"];
  $("strengthFill").style.background = colors[score];
}

function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => showPage(button.dataset.page));
  });

  document.querySelectorAll("[data-go]").forEach((button) => {
    button.addEventListener("click", () => showPage(button.dataset.go));
  });
}

function bindEncryptionMode() {
  document.querySelectorAll("#encryptMode .segment").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("#encryptMode .segment").forEach((b) => b.classList.remove("active"));
      button.classList.add("active");
      state.encryptMode = button.dataset.mode;

      $("passwordEncryptFields").classList.toggle("hidden", state.encryptMode !== "password");
      $("recipientEncryptFields").classList.toggle("hidden", state.encryptMode !== "recipient");
    });
  });
}

function credentials(prefix) {
  return {
    password: $(`${prefix}Password`)?.value || null,
    identityPath: $(`${prefix}Identity`)?.value || null,
    identityPassphrase: $(`${prefix}IdentityPassphrase`)?.value || null,
  };
}

async function run() {
  bindNavigation();
  bindEncryptionMode();

  $("encryptPassword").addEventListener("input", updateStrength);

  $("pickEncryptFile").onclick = () => chooseSingle("encryptFile").catch((e) => toast(e.message, true));
  $("pickEncryptSigner").onclick = () => chooseSingle("encryptSignerIdentity").catch((e) => toast(e.message, true));
  $("pickContactIdentity").onclick = () => chooseSingle("contactPublicIdentity").catch((e) => toast(e.message, true));
  $("pickDecryptFile").onclick = () => chooseSingle("decryptFile").catch((e) => toast(e.message, true));
  $("pickDecryptIdentity").onclick = () => chooseSingle("decryptIdentity").catch((e) => toast(e.message, true));
  $("pickInspectFile").onclick = () => chooseSingle("inspectFile").catch((e) => toast(e.message, true));
  $("pickInspectIdentity").onclick = () => chooseSingle("inspectIdentity").catch((e) => toast(e.message, true));
  $("pickAttackFile").onclick = () => chooseSingle("attackFile").catch((e) => toast(e.message, true));
  $("pickAttackIdentity").onclick = () => chooseSingle("attackIdentity").catch((e) => toast(e.message, true));

  $("pickRecipientKeys").onclick = async () => {
    try {
      const result = await bridgeCall("pick_public_identities");
      state.recipientKeys = result.paths || [];
      $("recipientKeys").value = state.recipientKeys.join("; ");
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("encryptAction").onclick = async () => {
    try {
      const input = $("encryptFile").value;
      if (!input) throw new Error("Choose an input file first.");

      let result;

      if (state.encryptMode === "password") {
        const password = $("encryptPassword").value;
        const confirm = $("encryptPasswordConfirm").value;

        if (!password) throw new Error("Enter a password.");
        if (password !== confirm) throw new Error("Passwords do not match.");

        result = await bridgeCall(
          "encrypt_password",
          input,
          password,
          $("encryptProfile").value,
          $("encryptSignerIdentity").value || null,
          $("encryptSignerPassphrase").value || null,
        );

        clearSecretFields("encryptPassword", "encryptPasswordConfirm", "encryptSignerPassphrase");
        updateStrength();
      } else {
        if (!state.recipientKeys.length) {
          throw new Error("Choose at least one recipient public key.");
        }

        result = await bridgeCall(
          "encrypt_recipients",
          input,
          state.recipientKeys,
          $("encryptSignerIdentity").value || null,
          $("encryptSignerPassphrase").value || null,
        );
        clearSecretFields("encryptSignerPassphrase");
      }

      toast(`Encrypted: ${result.output}`);
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("decryptAction").onclick = async () => {
    try {
      const input = $("decryptFile").value;
      if (!input) throw new Error("Choose an .aegis file.");

      const c = credentials("decrypt");
      const result = await bridgeCall(
        "decrypt_capsule",
        input,
        c.password,
        c.identityPath,
        c.identityPassphrase,
      );

      clearSecretFields("decryptPassword", "decryptIdentityPassphrase");
      toast(`Decrypted: ${result.output}`);
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("identityAction").onclick = async () => {
    try {
      const name = $("identityName").value.trim();
      const passphrase = $("identityPassphrase").value;
      const confirm = $("identityPassphraseConfirm").value;

      if (!name) throw new Error("Enter an identity name.");
      if (!passphrase) throw new Error("Enter a private-key passphrase.");
      if (passphrase !== confirm) throw new Error("Passphrases do not match.");

      const result = await bridgeCall("generate_identity", name, passphrase);
      clearSecretFields("identityPassphrase", "identityPassphraseConfirm");
      toast(`Identity created: ${result.public_key}`);
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("contactImportAction").onclick = async () => {
    try {
      const publicIdentity = $("contactPublicIdentity").value;
      if (!publicIdentity) throw new Error("Choose a public identity first.");

      const result = await bridgeCall(
        "import_contact",
        publicIdentity,
        $("contactTrust").value,
      );
      $("contactsResult").textContent = pretty(result.contact);
      toast(`Contact imported: ${result.contact.name}`);
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("contactsRefreshAction").onclick = async () => {
    try {
      const result = await bridgeCall("list_contacts");
      $("contactsResult").textContent = pretty(result.contacts);
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("inspectAction").onclick = async () => {
    try {
      const input = $("inspectFile").value;
      if (!input) throw new Error("Choose an .aegis file.");

      const result = await bridgeCall("inspect_capsule", input);
      $("inspectResult").textContent = pretty(result.report);
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("verifyAction").onclick = async () => {
    try {
      const input = $("inspectFile").value;
      if (!input) throw new Error("Choose an .aegis file.");

      const c = credentials("inspect");
      const result = await bridgeCall(
        "verify_capsule",
        input,
        c.password,
        c.identityPath,
        c.identityPassphrase,
      );

      $("inspectResult").textContent = pretty(result.report);
      clearSecretFields("inspectPassword", "inspectIdentityPassphrase");
      toast("Capsule verified.");
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("receiptAction").onclick = async () => {
    try {
      const input = $("inspectFile").value;
      if (!input) throw new Error("Choose an .aegis file.");

      const c = credentials("inspect");
      const result = await bridgeCall(
        "create_receipt",
        input,
        c.password,
        c.identityPath,
        c.identityPassphrase,
      );

      clearSecretFields("inspectPassword", "inspectIdentityPassphrase");
      toast(`Receipt created: ${result.output}`);
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("attackAction").onclick = async () => {
    try {
      const input = $("attackFile").value;
      if (!input) throw new Error("Choose an .aegis file.");

      const c = credentials("attack");
      const result = await bridgeCall(
        "simulate",
        input,
        c.password,
        c.identityPath,
        c.identityPassphrase,
      );

      clearSecretFields("attackPassword", "attackIdentityPassphrase");

      const box = $("attackResults");
      box.innerHTML = "";

      result.report.results.forEach((item) => {
        const row = document.createElement("div");
        row.className = "attack-row";
        row.innerHTML = `
          <span>${item.attack}</span>
          <strong class="${item.detected ? "ok" : "bad"}">
            ${item.detected ? "DETECTED" : "FAILED"}
          </strong>
        `;
        box.appendChild(row);
      });

      toast(
        `Detected ${result.report.attacks_detected}/${result.report.attacks_run} controlled attacks.`,
        !result.report.all_attacks_detected,
      );
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("planAction").onclick = async () => {
    try {
      const result = await bridgeCall(
        "plan",
        $("planSensitivity").value,
        Number($("planYears").value),
        $("planSharing").value,
        $("planRecovery").value,
        $("planQuantum").value,
      );

      $("planResult").textContent = pretty(result.plan);
    } catch (e) {
      toast(e.message, true);
    }
  };
}

window.addEventListener("pywebviewready", async () => {
  setBridgeStatus(true);
});

window.addEventListener("DOMContentLoaded", () => {
  run();

  setTimeout(() => {
    if (!window.pywebview?.api) {
      setBridgeStatus(false);
    }
  }, 800);
});
