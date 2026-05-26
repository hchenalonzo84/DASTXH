/*
  app.js
  - Inicializador general de la GUI DASTXH.

  Responsabilidad:
  - Cargar los módulos JavaScript separados.
  - Ejecutar la inicialización principal cuando el DOM esté listo.
  - Mantener app.js como archivo pequeño y fácil de mantener.

  Módulos cargados:
  - tabs.js
  - pagination.js
  - forms.js
  - execution_status.js

  Nota:
  - No agregues manualmente esos scripts en base.html si usas este loader.
  - Este archivo los carga automáticamente para evitar tocar la plantilla base.
*/

(function () {
  "use strict";

  /*
    Espacio global controlado para módulos de la GUI.
    Evita crear funciones sueltas en window.
  */
  window.DASTXHModules = window.DASTXHModules || {};

  /*
    Evita inicializar dos veces si el navegador recarga scripts
    o si algún cambio dinámico vuelve a ejecutar este archivo.
  */
  if (window.DASTXHAppInitialized === true) {
    return;
  }

  window.DASTXHAppInitialized = true;

  /*
    Lista de módulos que debe cargar la GUI.
    El orden importa:
    - tabs/pagination/forms son independientes.
    - execution_status puede apoyarse en hash actual al recargar.
  */
  const SCRIPT_PATHS = [
    "/static/js/tabs.js",
    "/static/js/pagination.js",
    "/static/js/forms.js",
    "/static/js/execution_status.js"
  ];

  /**
   * Espera a que el DOM esté disponible antes de ejecutar la inicialización.
   */
  function runWhenDomIsReady(callback) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", callback);
      return;
    }

    callback();
  }

  /**
   * Verifica si un script ya fue agregado al documento.
   */
  function isScriptAlreadyLoaded(src) {
    return Boolean(document.querySelector('script[src="' + src + '"]'));
  }

  /**
   * Carga un script de forma controlada.
   */
  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      if (isScriptAlreadyLoaded(src)) {
        resolve();
        return;
      }

      const script = document.createElement("script");

      script.src = src;
      script.defer = true;

      script.onload = function () {
        resolve();
      };

      script.onerror = function () {
        reject(new Error("No se pudo cargar el script: " + src));
      };

      document.head.appendChild(script);
    });
  }

  /**
   * Carga los módulos en secuencia para evitar condiciones de carrera.
   */
  function loadAllScriptsSequentially() {
    let chain = Promise.resolve();

    SCRIPT_PATHS.forEach(function (src) {
      chain = chain.then(function () {
        return loadScript(src);
      });
    });

    return chain;
  }

  /**
   * Ejecuta de forma segura un módulo si existe.
   */
  function initializeModule(moduleName, initializerName) {
    const moduleObject = window.DASTXHModules[moduleName];

    if (!moduleObject) {
      console.warn("Módulo no encontrado:", moduleName);
      return;
    }

    const initializer = moduleObject[initializerName];

    if (typeof initializer !== "function") {
      console.warn("Inicializador no encontrado:", moduleName + "." + initializerName);
      return;
    }

    initializer();
  }

  /**
   * Inicialización central de la GUI.
   */
  function initializeApp() {
    initializeModule("tabs", "initialize");
    initializeModule("pagination", "initialize");
    initializeModule("forms", "initialize");
    initializeModule("executionStatus", "initialize");
  }

  /*
    Arranque:
    1. Carga módulos.
    2. Espera DOM listo.
    3. Inicializa comportamiento de la GUI.
  */
  loadAllScriptsSequentially()
    .then(function () {
      runWhenDomIsReady(initializeApp);
    })
    .catch(function (error) {
      console.error("Error al cargar módulos de DASTXH:", error);
    });
})();