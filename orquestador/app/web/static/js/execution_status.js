/*
  execution_status.js
  - Refresco/estado de ejecución.

  Responsabilidad:
  - Detectar si la vista actual corresponde al detalle de una ejecución.
  - Leer el estado desde:
      #execution-status-meta
  - Si la ejecución está en estado initiated/running:
      * refrescar la página después de unos segundos.
  - Mantener la misma pestaña usando el hash de la URL.

  Nota:
  - Este módulo conserva el comportamiento simple del app.js anterior:
    refresco suave por timeout.
  - No cambia a polling por API para no modificar el comportamiento actual.
*/

(function () {
  "use strict";

  window.DASTXHModules = window.DASTXHModules || {};

  /**
   * Obtiene el bloque oculto con metadatos de la ejecución.
   */
  function getExecutionStatusMeta() {
    return document.getElementById("execution-status-meta");
  }

  /**
   * Normaliza un estado de ejecución.
   */
  function normalizeStatus(status) {
    return String(status || "").trim().toLowerCase();
  }

  /**
   * Devuelve true si el estado todavía requiere refresco.
   */
  function isPendingStatus(status) {
    return status === "initiated" || status === "running";
  }

  /**
   * Recarga la página conservando hash actual.
   */
  function reloadPreservingHash() {
    const hash = window.location.hash || "";
    const baseUrl = window.location.pathname + window.location.search;

    window.location.href = baseUrl + hash;
  }

  /**
   * Programa refresco suave si la ejecución sigue en curso.
   */
  function initializeExecutionAutoRefresh() {
    const meta = getExecutionStatusMeta();

    if (!meta) {
      return;
    }

    const status = normalizeStatus(meta.dataset.status);

    if (!isPendingStatus(status)) {
      return;
    }

    /*
      Tiempo de espera antes de refrescar.
      Se mantiene moderado para no saturar la GUI.
    */
    const refreshDelayMs = 7000;

    window.setTimeout(function () {
      reloadPreservingHash();
    }, refreshDelayMs);
  }

  /**
   * Inicializador público del módulo.
   */
  function initialize() {
    initializeExecutionAutoRefresh();
  }

  window.DASTXHModules.executionStatus = {
    initialize: initialize,
    reloadPreservingHash: reloadPreservingHash
  };
})();