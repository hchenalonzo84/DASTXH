/*
  app.js
  - Comportamiento cliente de la GUI DASTXH.

  Funciones principales:
  1. Mantener activa la pestaña indicada por hash (#general-report-pane, etc.).
  2. Actualizar el hash cuando el usuario cambia de pestaña.
  3. Paginar tablas largas de forma local.
  4. Evitar doble envío accidental de formularios normales.
  5. No bloquear formularios que abren PDF en pestaña nueva.
  6. Refrescar suavemente ejecuciones en estado initiated/running.
*/

(function () {
  "use strict";

  /**
   * Devuelve true si Bootstrap Tabs está disponible.
   */
  function hasBootstrapTabs() {
    return Boolean(window.bootstrap && window.bootstrap.Tab);
  }

  /**
   * Activa una pestaña por hash.
   *
   * Ejemplo:
   * #general-report-pane
   * #raw-pane
   * #artifacts-pane
   */
  function activateTabFromHash() {
    if (!hasBootstrapTabs()) {
      return;
    }

    const hash = window.location.hash;

    if (!hash) {
      return;
    }

    const targetPane = document.querySelector(hash);

    if (!targetPane) {
      return;
    }

    const tabButton = document.querySelector(
      `[data-bs-target="${hash}"], [href="${hash}"]`
    );

    if (!tabButton) {
      return;
    }

    const tab = new window.bootstrap.Tab(tabButton);
    tab.show();

    // Pequeño delay para que Bootstrap termine de mostrar la pestaña
    // antes de desplazar la vista.
    window.setTimeout(function () {
      const targetElement = document.querySelector(hash);

      if (targetElement) {
        targetElement.scrollIntoView({
          behavior: "smooth",
          block: "start"
        });
      }
    }, 120);
  }

  /**
   * Actualiza el hash cuando el usuario cambia de pestaña.
   */
  function bindTabHashUpdates() {
    const tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');

    tabButtons.forEach(function (button) {
      button.addEventListener("shown.bs.tab", function (event) {
        const target = event.target.getAttribute("data-bs-target");

        if (!target) {
          return;
        }

        if (window.location.hash === target) {
          return;
        }

        history.replaceState(null, "", target);
      });
    });
  }

  /**
   * Obtiene filas reales de una tabla.
   */
  function getTableRows(table) {
    const tbody = table.querySelector("tbody");

    if (!tbody) {
      return [];
    }

    return Array.from(tbody.querySelectorAll("tr"));
  }

  /**
   * Crea el contenedor visual de paginación.
   */
  function createPaginationControls(table, totalRows, pageSize) {
    const wrapper = document.createElement("div");
    wrapper.className = "table-pagination";

    const summary = document.createElement("div");
    summary.className = "table-pagination-summary";

    const controls = document.createElement("div");
    controls.className = "table-pagination-controls";

    const previousButton = document.createElement("button");
    previousButton.type = "button";
    previousButton.className = "table-pagination-button";
    previousButton.textContent = "Anterior";

    const pageIndicator = document.createElement("span");
    pageIndicator.className = "table-pagination-page-indicator";

    const nextButton = document.createElement("button");
    nextButton.type = "button";
    nextButton.className = "table-pagination-button";
    nextButton.textContent = "Siguiente";

    controls.appendChild(previousButton);
    controls.appendChild(pageIndicator);

    controls.appendChild(nextButton);

    wrapper.appendChild(summary);
    wrapper.appendChild(controls);

    return {
      wrapper,
      summary,
      previousButton,
      nextButton,
      pageIndicator,
      totalPages: Math.max(Math.ceil(totalRows / pageSize), 1)
    };
  }

  /**
   * Inserta controles de paginación después del wrapper visual correcto.
   */
  function insertPaginationAfterTable(table, paginationWrapper) {
    const tableResponsiveParent = table.closest(".table-responsive");

    if (tableResponsiveParent && tableResponsiveParent.parentNode) {
      tableResponsiveParent.parentNode.insertBefore(
        paginationWrapper,
        tableResponsiveParent.nextSibling
      );
      return;
    }

    table.parentNode.insertBefore(paginationWrapper, table.nextSibling);
  }

  /**
   * Inicializa paginación local para una tabla.
   */
  function initializePaginatedTable(table) {
    if (table.dataset.paginationInitialized === "true") {
      return;
    }

    const rows = getTableRows(table);
    const pageSize = parseInt(table.dataset.pageSize || "10", 10);
    const alwaysPaginate = table.dataset.alwaysPaginate === "true";

    if (!Number.isFinite(pageSize) || pageSize <= 0) {
      return;
    }

    if (rows.length <= pageSize && !alwaysPaginate) {
      return;
    }

    table.dataset.paginationInitialized = "true";

    let currentPage = 1;

    const pagination = createPaginationControls(
      table,
      rows.length,
      pageSize
    );

    function renderPage() {
      const startIndex = (currentPage - 1) * pageSize;
      const endIndex = startIndex + pageSize;

      rows.forEach(function (row, index) {
        if (index >= startIndex && index < endIndex) {
          row.hidden = false;
        } else {
          row.hidden = true;
        }
      });

      const visibleStart = rows.length === 0 ? 0 : startIndex + 1;
      const visibleEnd = Math.min(endIndex, rows.length);

      pagination.summary.textContent =
        "Mostrando " +
        visibleStart +
        "-" +
        visibleEnd +
        " de " +
        rows.length +
        " registros";

      pagination.pageIndicator.textContent =
        "Página " + currentPage + " de " + pagination.totalPages;

      pagination.previousButton.disabled = currentPage <= 1;
      pagination.nextButton.disabled = currentPage >= pagination.totalPages;
    }

    pagination.previousButton.addEventListener("click", function () {
      if (currentPage > 1) {
        currentPage -= 1;
        renderPage();
      }
    });

    pagination.nextButton.addEventListener("click", function () {
      if (currentPage < pagination.totalPages) {
        currentPage += 1;
        renderPage();
      }
    });

    insertPaginationAfterTable(table, pagination.wrapper);
    renderPage();
  }

  /**
   * Inicializa todas las tablas paginadas.
   */
  function initializePaginatedTables() {
    const tables = document.querySelectorAll(".js-paginated-table");

    tables.forEach(function (table) {
      initializePaginatedTable(table);
    });
  }
  /**
   * Devuelve true si el formulario abre resultado en pestaña nueva.
   *
   * Importante:
   * - Los formularios de impresión PDF usan target="_blank".
   * - Esos formularios NO deben quedar bloqueados, porque la GUI
   *   se mantiene abierta y el PDF se abre aparte.
   */
  function isNewTabForm(form) {
    const target = (form.getAttribute("target") || "").toLowerCase().trim();
    return target === "_blank";
  }

  /**
   * Deshabilita botones submit de un formulario normal para evitar doble envío.
   */
  function disableSubmitButtons(form) {
    const buttons = form.querySelectorAll('button[type="submit"], input[type="submit"]');

    buttons.forEach(function (button) {
      button.dataset.originalText = button.textContent || button.value || "";
      button.disabled = true;

      if (button.tagName.toLowerCase() === "button") {
        button.textContent = "Procesando...";
      } else {
        button.value = "Procesando...";
      }
    });
  }

  /**
   * Restaura botones de formularios target="_blank" si fuera necesario.
   */
  function restoreSubmitButtons(form) {
    const buttons = form.querySelectorAll('button[type="submit"], input[type="submit"]');

    buttons.forEach(function (button) {
      const originalText = button.dataset.originalText || "";

      button.disabled = false;

      if (originalText) {
        if (button.tagName.toLowerCase() === "button") {
          button.textContent = originalText;
        } else {
          button.value = originalText;
        }
      }
    });
  }

  /**
   * Protege formularios contra doble envío accidental.
   *
   * Reglas:
   * - Formularios normales: se bloquean después del submit.
   * - Formularios target="_blank": NO se bloquean permanentemente.
   *   Esto aplica a impresión PDF.
   */
  function initializeFormSubmitProtection() {
    const forms = document.querySelectorAll("form");

    forms.forEach(function (form) {
      if (form.dataset.submitProtectionInitialized === "true") {
        return;
      }

      form.dataset.submitProtectionInitialized = "true";

      form.addEventListener("submit", function (event) {
        // Si el formulario abre una pestaña nueva, no debemos dejar
        // la GUI bloqueada. El navegador abrirá la respuesta PDF aparte.
        if (isNewTabForm(form)) {
          window.setTimeout(function () {
            restoreSubmitButtons(form);
          }, 300);

          return;
        }

        // Si el formulario ya fue enviado, evitamos doble envío.
        if (form.dataset.submitted === "true") {
          event.preventDefault();
          return;
        }

        form.dataset.submitted = "true";
        disableSubmitButtons(form);
      });
    });
  }

  /**
   * Mantiene activa la pestaña Reporte general después de cargar con hash.
   */
  function initializeHashNavigation() {
    activateTabFromHash();
    bindTabHashUpdates();

    window.addEventListener("hashchange", function () {
      activateTabFromHash();
    });
  }

  /**
   * Refresca suavemente la página si la ejecución está en curso.
   *
   * Esto ayuda a que el usuario vea cuando termina sin presionar F5.
   */
  function initializeExecutionAutoRefresh() {
    const meta = document.getElementById("execution-status-meta");

    if (!meta) {
      return;
    }

    const status = (meta.dataset.status || "").toLowerCase();

    if (status !== "initiated" && status !== "running") {
      return;
    }

    const refreshDelayMs = 7000;

    window.setTimeout(function () {
      window.location.reload();
    }, refreshDelayMs);
  }

  /**
   * Ajusta enlaces externos/artifacts para que no se abran en la misma pestaña
   * cuando explícitamente tienen target _blank.
   */
  function initializeExternalLinkSafety() {
    const blankLinks = document.querySelectorAll('a[target="_blank"]');

    blankLinks.forEach(function (link) {
      if (!link.getAttribute("rel")) {
        link.setAttribute("rel", "noopener noreferrer");
      }
    });
  }

  /**
   * Inicialización principal.
   */
  function initializeApp() {
    initializeHashNavigation();
    initializePaginatedTables();
    initializeFormSubmitProtection();
    initializeExecutionAutoRefresh();
    initializeExternalLinkSafety();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeApp);
  } else {
    initializeApp();
  }
})();