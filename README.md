# OpenSMN

OpenSMN es una API opensource que actúa como proxy del Servicio Meteorológico Nacional (SMN) de Argentina, ofreciendo una forma sencilla y privada de acceder a sus datos públicos.

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

Para producción, es altamente recomendado usar un reverse proxy como nginx:

```nginx
location /smn/ {
    proxy_pass http://localhost:6942/smn/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## Licencia

El proyecto de openSMN es de código abierto y está licenciado bajo la GNU General Public License v2.0. no obstante, interacciona con el Servicio Meteorológico Nacional (SMN) de Argentina, servicio de codigo privativo.

No hay asociacion con este proyecto con el SMN ni con el gobierno argentino de ninguna manera
