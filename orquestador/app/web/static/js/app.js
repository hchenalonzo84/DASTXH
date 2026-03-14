/* ==========================================================
   app.js
   - Script base de la GUI web de DASTXH
   - En esta etapa su función es ligera:
     * verificar que el frontend cargó
     * mejorar un poco la experiencia del formulario
     * prevenir doble envío accidental
   ========================================================== */

document.addEventListener("DOMContentLoaded", () => {
    console.log("DASTXH web cargado correctamente");

    // ------------------------------------------------------
    // Formulario principal de escaneo
    // ------------------------------------------------------
    const scanForm = document.querySelector(".scan-form");

    if (scanForm) {
        const submitButton = scanForm.querySelector('button[type="submit"]');

        scanForm.addEventListener("submit", () => {
            // Evita doble clic accidental sobre el botón
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = "Ejecutando...";
            }
        });
    }

    // ------------------------------------------------------
    // Confirmación visual simple de la ruta actual
    // ------------------------------------------------------
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll(".topbar nav a");

    navLinks.forEach((link) => {
        const href = link.getAttribute("href");

        if (href && href === currentPath) {
            link.style.textDecoration = "underline";
        }
    });
});