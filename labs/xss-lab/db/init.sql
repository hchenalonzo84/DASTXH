-- =========================================================
-- init.sql
-- Base de datos propia del laboratorio xss-lab
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

CREATE TABLE IF NOT EXISTS reviews (
  id            BIGSERIAL PRIMARY KEY,
  product_id    BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  author_name   TEXT NOT NULL,
  rating        INT NOT NULL DEFAULT 5,
  comment_html  TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

INSERT INTO reviews (product_id, author_name, rating, comment_html)
SELECT
  p.id,
  'Cliente demo',
  5,
  'Buen producto para comenzar las pruebas del laboratorio.'
FROM products p
WHERE p.slug = 'smartphone-x1'
AND NOT EXISTS (
  SELECT 1
  FROM reviews r
  WHERE r.product_id = p.id
    AND r.author_name = 'Cliente demo'
);