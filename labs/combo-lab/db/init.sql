-- =========================================================
-- init.sql
-- Base de datos propia del laboratorio combinado combo-lab
-- =========================================================

CREATE TABLE IF NOT EXISTS products (
  id                 BIGSERIAL PRIMARY KEY,
  slug               TEXT NOT NULL UNIQUE,
  name               TEXT NOT NULL,
  price              NUMERIC(10,2) NOT NULL DEFAULT 0,
  short_description  TEXT NOT NULL DEFAULT '',
  description_html   TEXT NOT NULL DEFAULT '',
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO products (slug, name, price, short_description, description_html)
VALUES
(
  'smartphone-x1',
  'Smartphone X1',
  2499.99,
  'Teléfono con pantalla AMOLED y batería de larga duración.',
  '<p>Equipo orientado a productividad y entretenimiento.</p><p>Incluye cámara dual y carga rápida.</p>'
),
(
  'laptop-pro-14',
  'Laptop Pro 14',
  6899.00,
  'Portátil ligera para estudio y trabajo diario.',
  '<p>Procesador moderno, SSD y memoria suficiente para tareas académicas y de oficina.</p>'
),
(
  'audifonos-wave',
  'Audífonos Wave',
  399.50,
  'Audífonos inalámbricos con estuche de carga.',
  '<p>Diseñados para uso diario, música y videollamadas.</p>'
)
ON CONFLICT (slug) DO NOTHING;