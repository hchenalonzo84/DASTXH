/*
  pagination.js
  - Paginación local de tablas largas.

  Responsabilidad:
  - Aplicar paginación a tablas marcadas con:
      class="js-paginated-table"
      data-page-size="10"

  - Respetar:
      data-always-paginate="true"

  - Evitar duplicar controles si el inicializador se ejecuta más de una vez.

  Uso típico:
  <table class="table js-paginated-table" data-page-size="10">
*/

(function () {
  "use strict";

  window.DASTXHModules = window.DASTXHModules || {};

  /**
   * Obtiene las filas reales del tbody de una tabla.
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
  function createPaginationControls(totalRows, pageSize) {
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
    previousButton.setAttribute("aria-label", "Ir a la página anterior");

    const pageIndicator = document.createElement("span");
    pageIndicator.className = "table-pagination-page-indicator";

    const nextButton = document.createElement("button");
    nextButton.type = "button";
    nextButton.className = "table-pagination-button";
    nextButton.textContent = "Siguiente";
    nextButton.setAttribute("aria-label", "Ir a la página siguiente");

    controls.appendChild(previousButton);
    controls.appendChild(pageIndicator);
    controls.appendChild(nextButton);

    wrapper.appendChild(summary);
    wrapper.appendChild(controls);

    return {
      wrapper: wrapper,
      summary: summary,
      previousButton: previousButton,
      nextButton: nextButton,
      pageIndicator: pageIndicator,
      totalPages: Math.max(Math.ceil(totalRows / pageSize), 1)
    };
  }

  /**
   * Inserta la paginación después del wrapper visual correcto.
   *
   * Si la tabla está dentro de .table-responsive, los controles deben
   * quedar fuera de ese contenedor para no quedar atrapados por scroll.
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

    if (table.parentNode) {
      table.parentNode.insertBefore(paginationWrapper, table.nextSibling);
    }
  }

  /**
   * Inicializa paginación local en una tabla específica.
   */
  function initializePaginatedTable(table) {
    if (!table) {
      return;
    }

    if (table.dataset.paginationInitialized === "true") {
      return;
    }

    const rows = getTableRows(table);
    const pageSize = parseInt(table.dataset.pageSize || "10", 10);
    const alwaysPaginate = table.dataset.alwaysPaginate === "true";

    if (!Number.isFinite(pageSize) || pageSize <= 0) {
      return;
    }

    if (rows.length === 0) {
      return;
    }

    /*
      En tablas normales, no mostramos controles si no hace falta.
      En tablas marcadas con data-always-paginate="true", sí se muestran
      aunque la tabla tenga pocas filas.
    */
    if (rows.length <= pageSize && !alwaysPaginate) {
      table.dataset.paginationInitialized = "true";
      return;
    }

    table.dataset.paginationInitialized = "true";

    let currentPage = 1;

    const pagination = createPaginationControls(rows.length, pageSize);

    /**
     * Renderiza la página actual.
     */
    function renderPage() {
      const startIndex = (currentPage - 1) * pageSize;
      const endIndex = startIndex + pageSize;

      rows.forEach(function (row, index) {
        row.hidden = !(index >= startIndex && index < endIndex);
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
      if (currentPage <= 1) {
        return;
      }

      currentPage -= 1;
      renderPage();
    });

    pagination.nextButton.addEventListener("click", function () {
      if (currentPage >= pagination.totalPages) {
        return;
      }

      currentPage += 1;
      renderPage();
    });

    insertPaginationAfterTable(table, pagination.wrapper);
    renderPage();
  }

  /**
   * Inicializa todas las tablas paginadas en la vista actual.
   */
  function initialize() {
    const tables = document.querySelectorAll(".js-paginated-table");

    tables.forEach(function (table) {
      initializePaginatedTable(table);
    });
  }

  window.DASTXHModules.pagination = {
    initialize: initialize,
    initializePaginatedTable: initializePaginatedTable
  };
})();