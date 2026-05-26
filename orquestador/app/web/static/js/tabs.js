/*
  tabs.js
  - Manejo de pestañas Bootstrap y navegación por hash.

  Responsabilidad:
  - Activar una pestaña cuando la URL trae hash.
    Ejemplos:
      /executions/1#general-report-pane
      /executions/1#raw-pane
      /executions/1#artifacts-pane

  - Actualizar el hash cuando el usuario cambia de pestaña.
  - Mantener la navegación estable al consultar versiones históricas
    o al volver a Reporte general.
*/

(function () {
  "use strict";

  window.DASTXHModules = window.DASTXHModules || {};

  /**
   * Devuelve true si Bootstrap Tabs está disponible.
   */
  function hasBootstrapTabs() {
    return Boolean(window.bootstrap && window.bootstrap.Tab);
  }

  /**
   * Busca el botón de pestaña asociado a un panel por hash.
   */
  function findTabButtonByHash(hash) {
    if (!hash) {
      return null;
    }

    return document.querySelector(
      '[data-bs-target="' + hash + '"], [href="' + hash + '"]'
    );
  }

  /**
   * Activa una pestaña usando el hash actual de la URL.
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

    const tabButton = findTabButtonByHash(hash);

    if (!tabButton) {
      return;
    }

    const tab = new window.bootstrap.Tab(tabButton);
    tab.show();

    /*
      Pequeño delay para que Bootstrap termine de mostrar
      la pestaña antes de desplazar la vista.
    */
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
      if (button.dataset.hashBindingInitialized === "true") {
        return;
      }

      button.dataset.hashBindingInitialized = "true";

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
   * Inicializa navegación por hash.
   */
  function initialize() {
    activateTabFromHash();
    bindTabHashUpdates();

    window.addEventListener("hashchange", function () {
      activateTabFromHash();
    });
  }

  window.DASTXHModules.tabs = {
    initialize: initialize,
    activateTabFromHash: activateTabFromHash
  };
})();