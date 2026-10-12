# OpenSOC Unified Security

Aplicación independiente para importar, consolidar y exportar observaciones de auditorías.

**Estado:** prototipo inicial, no producto terminado. Aún no está validada su compatibilidad con todos los JSON de Offensive AI.

## Inicio
Requiere Python 3.10+; no necesita Docker.

- Linux/Kali: `sh start.sh`
- Windows: doble clic en `start.bat`

Abrir http://127.0.0.1:8770

## Funciones iniciales
- Importar JSON local con observaciones reconocidas.
- Deduplicación conservadora con conservación de fuentes.
- Exportar JSON técnico y una versión compartible con redacción básica.
- Almacenar datos solo en `data/` (excluido del repositorio).

**Advertencia:** la redacción automática no garantiza anonimización total. Revisar el informe antes de compartirlo.

## Pruebas
`python -m unittest discover -s tests -v`

## Pendiente
Interfaz de selección de secciones, PDF, borrado de sesiones, autenticación local, cifrado, integración de motores y ejecutables instalables verificados. No subir evidencia confidencial a GitHub.
