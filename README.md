<img width="114" height="67" alt="OpenSMN logo, Un pato" src="https://github.com/user-attachments/assets/66613c67-e68c-4889-aebe-a03c0448273c" />

# OpenSMN

OpenSMN es una API opensource que actúa como proxy del Servicio Meteorológico Nacional (SMN) de Argentina, ofreciendo una forma sencilla y privada de acceder a sus datos públicos.

## ¿Por qué es necesaria esta API?

El Servicio Meteorológico Nacional de Argentina **no cuenta con una API pública completa y accesible**. Aunque existe un endpoint oficial, este presenta serias limitaciones:

- **Requiere autenticación obligatoria**: El acceso a los datos meteorológicos públicos está bloqueado detrás de un sistema de tokens.
- **Obtención poco transparente del token**: El token de autenticación no se puede obtener mediante un proceso oficial documentado; la única forma de conseguirlo es mediante scraping de la página web del SMN.
- **Falta de documentación**: No existe documentación oficial sobre cómo utilizar correctamente el endpoint o cómo solicitar credenciales de acceso.
- **Barreras innecesarias**: Para datos que deberían ser de acceso público y libre, se imponen restricciones técnicas que dificultan su uso por parte de desarrolladores, investigadores y ciudadanos.

## Requisitos

- Python 3.7+
- ChromeDriver

## Instalación

1. Clona el repositorio:

```bash
git clone https://github.com/nixietab/OpenSMN
cd OpenSMN
```

2. Instala las dependencias:

```bash
pip install -r requirements.txt
```

3. Configura las variables de entorno:

```bash
cp .env.example .env
```

Edita el archivo `.env` con tu configuración, puedes ver todas las variables en el archivo `.env.example`.

## Uso

### Desarrollo

Para ejecutar el servidor en modo desarrollo:

```bash
uvicorn server:app --reload --port 6942
```

### Producción

Para ejecutar el servidor en producción, usa el script `start.sh`:

```bash
./start.sh
```

El script carga automáticamente las variables de entorno desde `.env` y ejecuta la api.

## Autenticación

Si configuras un `PASSWORD` en tu `.env`, todas las peticiones deben incluir el header:

```
Authorization: clave_ultra_segura
```

## Despliegue con Reverse Proxy

Para producción, es altamente recomendado usar un reverse proxy como nginx, esto es un ejemplo de como configurarlo:

```nginx
location /smn/ {
    proxy_pass http://localhost:6942/smn/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Rate limiting adicional a nivel de nginx (opcional)
    limit_req zone=api_limit burst=20 nodelay;
    
    # Timeouts
    proxy_connect_timeout 10s;
    proxy_send_timeout 10s;
    proxy_read_timeout 30s;
}
```

## Licencia

El proyecto OpenSMN es de código abierto y se distribuye bajo la licencia GNU General Public License v2.0. Sin embargo, interactúa con el Servicio Meteorológico Nacional (SMN) de Argentina, el cual es de carácter privativo.

OpenSMN no mantiene ninguna relación, afiliación ni respaldo oficial por parte del SMN ni del Gobierno Argentino.
