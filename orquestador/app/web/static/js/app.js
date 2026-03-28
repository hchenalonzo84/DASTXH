/* ==========================================================
   app.js
   - Script principal de la GUI web de DASTXH
   - Esta versión agrega:
     * prevención de doble envío en el formulario
     * resaltado del enlace activo
     * polling automático en detalle de ejecución
     * soporte de pestañas Bootstrap
     * persistencia de pestaña activa por hash
   ========================================================== */

document.addEventListener("DOMContentLoaded", () => {
    console.log("DASTXH web cargado correctamente");

    setupScanForm();
    highlightCurrentNavLink();
    setupBootstrapTabs();
    setupExecutionPolling();
});


/* ==========================================================
   FORMULARIO PRINCIPAL
   ========================================================== */

function setupScanForm() {
    /*
      Evita doble envío accidental del formulario principal.
    */
    const scanForm = document.querySelector(".scan-form");

    if (!scanForm) {
        return;
    }

    const submitButton = scanForm.querySelector('button[type="submit"]');

    scanForm.addEventListener("submit", () => {
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = "Ejecutando...";
        }
    });
}


/* ==========================================================
   NAVEGACIÓN SUPERIOR
   ========================================================== */

function highlightCurrentNavLink() {
    /*
      Subraya el enlace activo del menú superior.
    */
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll(".topbar nav a");

    navLinks.forEach((link) => {
        const href = link.getAttribute("href");

        if (href && href === currentPath) {
            link.style.textDecoration = "underline";
        }
    });
}


/* ==========================================================
   PESTAÑAS BOOTSTRAP
   ========================================================== */

function setupBootstrapTabs() {
    /*
      Activa comportamiento adicional para las pestañas:
      - si la URL tiene hash (#raw-pane, #artifacts-pane, etc.),
        abre esa pestaña al cargar
      - cuando el usuario cambia de pestaña, actualiza el hash
        sin saltos bruscos
    */
    const tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');

    if (!tabButtons.length || typeof bootstrap === "undefined") {
        return;
    }

    // ------------------------------------------------------
    // Al cargar: intentar abrir la pestaña indicada en hash
    // ------------------------------------------------------
    const currentHash = window.location.hash;
    if (currentHash) {
        const matchingButton = document.querySelector(
            `[data-bs-target="${currentHash}"]`
        );

        if (matchingButton) {
            const tab = new bootstrap.Tab(matchingButton);
            tab.show();
        }
    }

    // ------------------------------------------------------
    // Al cambiar de pestaña: actualizar hash
    // ------------------------------------------------------
    tabButtons.forEach((button) => {
        button.addEventListener("shown.bs.tab", (event) => {
            const targetSelector = event.target.getAttribute("data-bs-target");
            if (!targetSelector) {
                return;
            }

            // Reemplaza el hash sin mover la página bruscamente
            history.replaceState(null, "", targetSelector);
        });
    });
}


/* ==========================================================
   POLLING DE EJECUCIÓN
   ========================================================== */

function setupExecutionPolling() {
    /*
      Solo aplica en la vista de detalle de ejecución.
      Busca el bloque oculto:
      #execution-status-meta

      Si el estado es initiated o running:
      - consulta /api/scans/{id}
      - si cambia a finished o failed, recarga
      - mantiene la pestaña actual usando el hash
    */
    const meta = document.getElementById("execution-status-meta");

    if (!meta) {
        return;
    }

    const executionId = Number(meta.dataset.executionId || "");
    const initialStatus = String(meta.dataset.status || "").trim().toLowerCase();

    if (!Number.isInteger(executionId) || executionId <= 0) {
        console.warn("Polling omitido: execution_id inválido.");
        return;
    }

    const pendingStatuses = new Set(["initiated", "running"]);
    if (!pendingStatuses.has(initialStatus)) {
        return;
    }

    console.log(`Iniciando polling para ejecución ${executionId} con estado ${initialStatus}`);

    const pollIntervalMs = 5000;
    const maxPollingMs = 10 * 60 * 1000; // 10 minutos
    const startTime = Date.now();

    let lastKnownStatus = initialStatus;
    const timerId = window.setInterval(async () => {
        try {
            if (Date.now() - startTime > maxPollingMs) {
                console.warn("Polling detenido por tiempo máximo alcanzado.");
                window.clearInterval(timerId);
                return;
            }

            const response = await fetch(`/api/scans/${executionId}`, {
                method: "GET",
                headers: {
                    "Accept": "application/json"
                },
                cache: "no-store"
            });

            if (!response.ok) {
                console.warn(`Polling: respuesta no OK (${response.status}).`);
                return;
            }

            const data = await response.json();
            const execution = data && data.execution ? data.execution : null;

            if (!execution) {
                console.warn("Polling: no se recibió objeto execution.");
                return;
            }

            const currentStatus = String(execution.status || "").trim().toLowerCase();
            if (!currentStatus) {
                return;
            }

            updateVisibleExecutionStatus(currentStatus);

            // Si terminó, recargar manteniendo hash/pestaña actual
            if (currentStatus === "finished" || currentStatus === "failed") {
                console.log(`La ejecución ${executionId} terminó con estado ${currentStatus}. Recargando vista.`);
                window.clearInterval(timerId);
                reloadPreservingHash();
                return;
            }

            // Si cambió a otro estado intermedio, actualizar referencia
            if (currentStatus !== lastKnownStatus) {
                console.log(
                    `La ejecución ${executionId} cambió de ${lastKnownStatus} a ${currentStatus}.`
                );
                lastKnownStatus = currentStatus;
            }
        } catch (error) {
            console.warn("Error durante polling de ejecución:", error);
        }
    }, pollIntervalMs);
}


/* ==========================================================
   ACTUALIZACIÓN VISUAL LIGERA
   ========================================================== */

function updateVisibleExecutionStatus(status) {
    /*
      Mejora visual ligera mientras corre el polling:
      - actualiza el data-status del bloque meta
      - intenta actualizar el primer badge visible
    */
    const meta = document.getElementById("execution-status-meta");
    if (meta) {
        meta.dataset.status = status;
    }

    const badge = document.querySelector(".badge");
    if (!badge) {
        return;
    }

    badge.classList.remove(
        "badge-initiated",
        "badge-running",
        "badge-finished",
        "badge-failed"
    );

    badge.classList.add(`badge-${status}`);
    badge.textContent = status;
}


/* ==========================================================
   RECARGA CONSERVANDO HASH
   ========================================================== */

function reloadPreservingHash() {
    /*
      Recarga la página manteniendo la pestaña actual.
      Si el usuario estaba en #raw-pane o #artifacts-pane,
      regresará ahí mismo después del reload.
    */
    const hash = window.location.hash || "";
    const baseUrl = window.location.pathname + window.location.search;
    window.location.href = `${baseUrl}${hash}`;
}