# TZOOTZ RESEARCH 2025® Network & Port Scanner

## Descripción

**TZOOTZ RESEARCH 2025® Network & Port Scanner** es una herramienta visual desarrollada en Python para escanear redes y puertos de forma eficiente y fácil de usar. Diseñada con un enfoque en simplicidad y robustez, esta aplicación permite diagnosticar conectividad de red y verificar el estado de puertos en sistemas objetivos.

---

## Características

### Escáner de Red
- **Detección de Hosts Activos**: Escanea subredes completas para identificar dispositivos activos.
- **Ping Automático**: Verifica conectividad con cada IP en la subred.
- **Hostname Resolution**: Intenta resolver el nombre de host de cada IP encontrada.
- **Resultados en Tiempo Real**: Visualización de resultados a medida que se procesan.

### Escáner de Puertos
- **Escaneo por Rango**: Define un rango personalizado de puertos a escanear.
- **Estado del Puerto**: Identifica si los puertos están abiertos, cerrados o filtrados.
- **Resolución de Servicios**: Detecta servicios asociados a puertos abiertos.
- **Multihilo**: Utiliza hilos para acelerar los escaneos.

### Interfaz Gráfica (GUI)
- Diseño moderno y minimalista con **Tkinter**.
- Opciones intuitivas para iniciar y detener escaneos.
- Visualización jerárquica (Treeview) para presentar los resultados de red y puertos.

---

## Tecnologías y Dependencias

- **Lenguaje**: Python 3.9+
- **Módulos Estándar**:
  - `socket`
  - `threading`
  - `queue`
  - `subprocess`
  - `ipaddress`
  - `time`
- **Interfaz Gráfica**: Tkinter

---

## Instalación

1. **Clonar el Repositorio**:
   ```bash
   git clone https://github.com/tuusuario/tzootz-research-scanner.git
   cd tzootz-research-scanner
   ```

2. **Ejecutar el Script**:
   Asegúrate de tener Python 3.9 o superior instalado.
   ```bash
   python3 ST_port_scanner.py
   ```

---

## Uso

1. **Escaneo de Red**:
   - Presiona el botón **Scan Network** para iniciar el escaneo de toda la subred local.
   - Los resultados aparecerán en la tabla de resultados de red.

2. **Escaneo de Puertos**:
   - Introduce la IP objetivo y el rango de puertos.
   - Presiona el botón **Scan Ports** para iniciar.
   - Los resultados de cada puerto escaneado se mostrarán en tiempo real.

---

## Ejemplo de Pantalla

![Captura de Pantalla] screenshot.png *(Incluir una captura si la tienes)*

---

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

## Contribuciones

Si deseas contribuir al proyecto, realiza un fork del repositorio, realiza tus cambios y abre un Pull Request.

---

## Contacto

Desarrollado por **Fundación Mosquera - TZOOTZ RESEARCH 2025®**.
- Email: [me@tzootz.com](mailto:me@tzootz.com)
- Sitio web: [tzootz.com](https://tzootz.com)
