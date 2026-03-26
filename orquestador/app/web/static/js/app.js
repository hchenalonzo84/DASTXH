/* ==========================================================
   app.js
   - Script base de la GUI web de DASTXH
   - Esta versión agrega:
     * prevención de doble envío en el formulario
     * subrayado simple del enlace activo en la barra superior
     * polling automático en la vista de detalle de ejecución
       cuando el estado sea "initiated" o "running"

   Objetivo del polling:
   - permitir que la página de detalle detecte cuándo el escaneo
     terminó en segundo plano
   - recargar automáticamente la vista al finalizar
   - evitar que el usuario tenga que refrescar manualmente
========================================================== */

document.addEventListener("DOMContentLoaded", () => {
    console.log("DASTXH web cargado correctamente");

    // ------------------------------------------------------
    // 1) Mejorar experiencia del formulario principal
    // ------------------------------------------------------
    setupScanForm();

    // ------------------------------------------------------
    // 2) Resaltar enlace activo en la navegación superior
    // ------------------------------------------------------
    highlightCurrentNavLink();

    // ------------------------------------------------------
    // 3) Activar seguimiento automático de ejecuciones
    //    si estamos en la página de detalle
    // ------------------------------------------------------
    setupExecutionPolling();
});


/* ==========================================================
   FORMULARIO PRINCIPAL
========================================================== */
function setupScanForm() {
    /* Busca el formulario principal de escaneo y evita
       que el usuario haga doble clic accidental sobre
       el botón submit. */
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
    /* Subraya el enlace activo de la barra superior para dar
       una referencia visual simple al usuario. */
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
   POLLING DE EJECUCIÓN
========================================================== */
function setupExecutionPolling() {
    /* Esta función solo actúa si existe el bloque oculto
       #execution-status-meta, el cual agregamos en
       execution_detail.html.

       Ejemplo esperado:
       <div
           id="execution-status-meta"
           data-execution-id="15"
           data-status="running"
           hidden
       ></div>
    */
    const meta = document.getElementById("execution-status-meta");

    // Si no existe ese bloque, no estamos en detalle de ejecución
    if (!meta) {
        return;
    }

    const executionId = Number(meta.dataset.executionId || "");
    const initialStatus = String(meta.dataset.status || "").trim().toLowerCase();

    // Validación defensiva básica
    if (!Number.isInteger(executionId) || executionId <= 0) {
        console.warn("Polling omitido: execution_id inválido.");
        return;
    }

    // Solo activamos polling si la ejecución todavía podría cambiar
    const pendingStatuses = new Set(["initiated", "running"]);

    if (!pendingStatuses.has(initialStatus)) {
        return;
    }

    console.log(`Iniciando polling para ejecución ${executionId} con estado ${initialStatus}`);

    // Intervalo de consulta en milisegundos
    const pollIntervalMs = 5000;

    // Límite máximo de tiempo para no dejar polling infinito
    // si la página queda abierta demasiado tiempo.
    const maxPollingMs = 10 * 60 * 1000; // 10 minutos

    const startTime = Date.now();

    // Guardamos el último estado conocido para detectar cambios
    let lastKnownStatus = initialStatus;
        const timerId = window.setInterval(async () => {
        try {
            // Si ya superó el tiempo máximo, detenemos el polling
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

            // Si no vino estado, no hacemos nada
            if (!currentStatus) {
                return;
            }

            // --------------------------------------------------
            // Actualización visual mínima en la página actual
            // antes de recargar por completo
            // --------------------------------------------------
            updateVisibleExecutionStatus(currentStatus);

            // --------------------------------------------------
            // Si el estado cambió con respecto al que conocíamos,
            // recargamos la página para traer todo el detalle nuevo
            // (resultados, artifacts, mensajes, etc.)
            // --------------------------------------------------
            if (currentStatus !== lastKnownStatus) {
                console.log(
                    `La ejecución ${executionId} cambió de ${lastKnownStatus} a ${currentStatus}. Recargando vista.`
                );
                window.clearInterval(timerId);
                window.location.reload();
                return;
            }

            // --------------------------------------------------
            // Incluso si no detectamos "cambio" localmente,
            // si el backend ya reporta un estado final, recargamos.
            // Esto cubre casos donde el DOM se abrió ya en estado
            // "running" y sigue "running" varias consultas, hasta
            // que finalmente termine.
            // --------------------------------------------------
            if (currentStatus === "finished" || currentStatus === "failed") {
                console.log(`La ejecución ${executionId} terminó con estado ${currentStatus}. Recargando vista.`);
                window.clearInterval(timerId);
                window.location.reload();
                return;
            }

            // Guardar el último estado conocido
            lastKnownStatus = currentStatus;
        } catch (error) {
            console.warn("Error durante polling de ejecución:", error);
        }
    }, pollIntervalMs);
}


/* ==========================================================
   ACTUALIZACIÓN VISUAL LIGERA DEL ESTADO
========================================================== */
function updateVisibleExecutionStatus(status) {
    /* Esta función hace una mejora visual mínima mientras el
       polling está activo:

       - actualiza el atributo data-status del bloque meta
       - intenta actualizar el primer badge de estado visible

       No sustituye la recarga final completa, pero ayuda a que
       la interfaz no quede tan estática mientras se consulta.
    */
    const meta = document.getElementById("execution-status-meta");

    if (meta) {
        meta.dataset.status = status;
    }

    const badge = document.querySelector(".badge");

    if (!badge) {
        return;
    }

    // Limpiamos clases anteriores conocidas
    badge.classList.remove(
        "badge-initiated",
        "badge-running",
        "badge-finished",
        "badge-failed"
    );

    // Aplicamos la nueva clase y texto
    badge.classList.add(`badge-${status}`);
    badge.textContent = status;
}