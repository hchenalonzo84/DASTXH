/*
  forms.js
  - Manejo de formularios, botones y enlaces externos.

  Responsabilidad:
  - Evitar doble envío accidental en formularios normales.
  - No bloquear formularios que abren PDF en pestaña nueva.
  - Restaurar botones cuando el formulario usa target="_blank".
  - Asegurar rel="noopener noreferrer" en enlaces target="_blank".

  Importante:
  - Los formularios de impresión PDF usan target="_blank".
  - Esos formularios NO deben dejar la GUI bloqueada.
*/

(function () {
  "use strict";

  window.DASTXHModules = window.DASTXHModules || {};

  /**
   * Devuelve true si el formulario abre resultado en una pestaña nueva.
   */
  function isNewTabForm(form) {
    const target = (form.getAttribute("target") || "").toLowerCase().trim();
    return target === "_blank";
  }

  /**
   * Obtiene todos los botones submit de un formulario.
   */
  function getSubmitButtons(form) {
    return form.querySelectorAll('button[type="submit"], input[type="submit"]');
  }

  /**
   * Guarda el texto original de un botón para poder restaurarlo.
   */
  function storeOriginalButtonText(button) {
    if (button.dataset.originalText) {
      return;
    }

    button.dataset.originalText = button.textContent || button.value || "";
  }

  /**
   * Cambia el texto visible de un botón.
   */
  function setButtonText(button, text) {
    if (button.tagName.toLowerCase() === "button") {
      button.textContent = text;
      return;
    }

    button.value = text;
  }

  /**
   * Restaura el texto original de un botón.
   */
  function restoreButtonText(button) {
    const originalText = button.dataset.originalText || "";

    if (!originalText) {
      return;
    }

    setButtonText(button, originalText);
  }

  /**
   * Deshabilita botones submit para evitar doble envío.
   */
  function disableSubmitButtons(form) {
    const buttons = getSubmitButtons(form);

    buttons.forEach(function (button) {
      storeOriginalButtonText(button);
      button.disabled = true;
      setButtonText(button, "Procesando...");
    });
  }

  /**
   * Restaura botones de un formulario.
   */
  function restoreSubmitButtons(form) {
    const buttons = getSubmitButtons(form);

    buttons.forEach(function (button) {
      button.disabled = false;
      restoreButtonText(button);
    });
  }

  /**
   * Protege un formulario individual contra doble envío.
   */
  function initializeFormSubmitProtection(form) {
    if (!form) {
      return;
    }

    if (form.dataset.submitProtectionInitialized === "true") {
      return;
    }

    form.dataset.submitProtectionInitialized = "true";

    form.addEventListener("submit", function (event) {
      /*
        Formularios target="_blank":
        - se usan para abrir PDF en otra pestaña.
        - no deben bloquear la GUI.
      */
      if (isNewTabForm(form)) {
        window.setTimeout(function () {
          restoreSubmitButtons(form);
        }, 300);

        return;
      }

      /*
        Formularios normales:
        - se bloquean después del primer submit para evitar duplicados.
      */
      if (form.dataset.submitted === "true") {
        event.preventDefault();
        return;
      }

      form.dataset.submitted = "true";
      disableSubmitButtons(form);
    });
  }

  /**
   * Inicializa protección en todos los formularios.
   */
  function initializeAllForms() {
    const forms = document.querySelectorAll("form");

    forms.forEach(function (form) {
      initializeFormSubmitProtection(form);
    });
  }

  /**
   * Asegura que los enlaces target="_blank" no expongan window.opener.
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
   * Inicializador público del módulo.
   */
  function initialize() {
    initializeAllForms();
    initializeExternalLinkSafety();
  }

  window.DASTXHModules.forms = {
    initialize: initialize,
    initializeFormSubmitProtection: initializeFormSubmitProtection,
    restoreSubmitButtons: restoreSubmitButtons
  };
})();