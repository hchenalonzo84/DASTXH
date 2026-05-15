/* ==========================================================
   app.js
   - Script principal de la GUI web de DASTXH
   - Esta versión agrega:
     * prevención de doble envío en el formulario
     * resaltado del enlace activo
     * polling automático en detalle de ejecución
     * soporte de pestañas Bootstrap
     * persistencia de pestaña activa por hash
     * paginación local simple para tablas largas
     * paginación visible siempre en la tabla XSS
   ========================================================== */

document.addEventListener("DOMContentLoaded", () => {
    console.log("DASTXH web cargado correctamente");

    setupScanForm();
    highlightCurrentNavLink();
    setupBootstrapTabs();
    setupPaginatedTables();
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

    tabButtons.forEach((button) => {
        button.addEventListener("shown.bs.tab", (event) => {
            const targetSelector = event.target.getAttribute("data-bs-target");

            if (!targetSelector) {
                return;
            }

            history.replaceState(null, "", targetSelector);
        });
    });
}
/* ==========================================================
   PAGINACIÓN LOCAL DE TABLAS
   ========================================================== */

function setupPaginatedTables() {
    /*
      Aplica paginación local a las tablas marcadas con:

      class="js-paginated-table"
      data-page-size="10"

      Ajuste importante:
      - En tablas normales, si hay 10 filas o menos, no se muestran controles.
      - En la tabla XSS, los controles se muestran siempre para que el usuario
        identifique claramente el total visible, aunque solo exista 1 hallazgo.
    */
    const tables = document.querySelectorAll(".js-paginated-table");

    tables.forEach((table, index) => {
        setupSinglePaginatedTable(table, index);
    });
}


function setupSinglePaginatedTable(table, tableIndex) {
    /*
      Configura la paginación de una sola tabla.

      Defensa:
      Si esta función se ejecuta más de una vez, no duplica controles.
    */
    if (!table || table.dataset.paginationReady === "true") {
        return;
    }

    const tbody = table.querySelector("tbody");

    if (!tbody) {
        return;
    }

    const rows = Array.from(tbody.querySelectorAll("tr"));
    const totalRows = rows.length;

    if (totalRows === 0) {
        return;
    }

    const configuredPageSize = Number(table.dataset.pageSize || "10");
    const pageSize = Number.isInteger(configuredPageSize) && configuredPageSize > 0
        ? configuredPageSize
        : 10;

    /*
      La tabla XSS debe mostrar paginación siempre, incluso con 1 fila.
      Esto ayuda a que el total visible quede claro para el usuario.
    */
    const forcePagination =
        table.classList.contains("xss-results-table") ||
        table.dataset.alwaysPaginate === "true";

    /*
      En tablas normales, si no superan el tamaño de página,
      no se agregan controles innecesarios.
    */
    if (totalRows <= pageSize && !forcePagination) {
        table.dataset.paginationReady = "true";
        return;
    }

    const totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
    let currentPage = 1;

    table.dataset.paginationReady = "true";

    const paginationContainer = document.createElement("div");
    paginationContainer.className = "table-pagination";
    paginationContainer.dataset.tableIndex = String(tableIndex + 1);

    const summary = document.createElement("div");
    summary.className = "table-pagination-summary";

    const controls = document.createElement("div");
    controls.className = "table-pagination-controls";

    const previousButton = createPaginationButton(
        "Anterior",
        "Ir a la página anterior"
    );

    const nextButton = createPaginationButton(
        "Siguiente",
        "Ir a la página siguiente"
    );

    const pageIndicator = document.createElement("span");
    pageIndicator.className = "table-pagination-page-indicator";

    previousButton.addEventListener("click", () => {
        if (currentPage <= 1) {
            return;
        }

        currentPage -= 1;
        renderPaginatedTable();
    });

    nextButton.addEventListener("click", () => {
        if (currentPage >= totalPages) {
            return;
        }

        currentPage += 1;
        renderPaginatedTable();
    });

    controls.appendChild(previousButton);
    controls.appendChild(pageIndicator);
    controls.appendChild(nextButton);

    paginationContainer.appendChild(summary);
    paginationContainer.appendChild(controls);

    const responsiveWrapper = table.closest(".table-responsive");

    if (responsiveWrapper && responsiveWrapper.parentNode) {
        responsiveWrapper.insertAdjacentElement("afterend", paginationContainer);
    } else {
        table.insertAdjacentElement("afterend", paginationContainer);
    }

    function renderPaginatedTable() {
        const startIndex = (currentPage - 1) * pageSize;
        const endIndex = Math.min(startIndex + pageSize, totalRows);

        rows.forEach((row, rowIndex) => {
            const isVisible = rowIndex >= startIndex && rowIndex < endIndex;
            row.hidden = !isVisible;
        });

        summary.textContent = `Mostrando ${startIndex + 1}-${endIndex} de ${totalRows} registros`;
        pageIndicator.textContent = `Página ${currentPage} de ${totalPages}`;

        previousButton.disabled = currentPage <= 1;
        nextButton.disabled = currentPage >= totalPages;
    }

    renderPaginatedTable();
}


function createPaginationButton(text, ariaLabel) {
    /*
      Crea un botón reutilizable para los controles de paginación.
    */
    const button = document.createElement("button");

    button.type = "button";
    button.className = "table-pagination-button";
    button.textContent = text;
    button.setAttribute("aria-label", ariaLabel);

    return button;
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
    const maxPollingMs = 10 * 60 * 1000;
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

            if (currentStatus === "finished" || currentStatus === "failed") {
                console.log(`La ejecución ${executionId} terminó con estado ${currentStatus}. Recargando vista.`);
                window.clearInterval(timerId);
                reloadPreservingHash();
                return;
            }

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