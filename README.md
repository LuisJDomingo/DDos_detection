DDoSDetector
Descripción
DDoSDetector es una aplicación en Python diseñada para detectar posibles ataques DDoS (Denegación de Servicio Distribuida) basándose en la frecuencia de las solicitudes recibidas desde una dirección IP específica. La aplicación utiliza un umbral de solicitudes y una ventana de tiempo para determinar si una dirección IP está realizando demasiadas solicitudes en un período corto, lo que podría indicar un ataque DDoS.

Instalación
Para instalar y ejecutar esta aplicación, sigue los siguientes pasos:

1. Clona este repositorio en tu máquina local:
```bash
git clone https://github.com/tu_usuario/DDoSDetector.git
```
2. Navega al directorio del proyecto:
```bash
cd DDoSDetector
```
3. Asegúrate de tener Python 3 instalado en tu sistema. Puedes verificarlo ejecutando:
```bash
python3 --version
```
4 Instala las dependencias necesarias (en este caso, no hay dependencias externas adicionales):
```bash
pip install -r requirements.txt
```

Explicación del Código
El archivo principal de la aplicación es main.py, que contiene la clase DDoSDetector y una simulación de uso.

Clase DDoSDetector
Atributos
threshold: Número máximo de solicitudes permitidas desde una dirección IP dentro de la ventana de tiempo antes de que se considere un ataque DDoS.
time_window: Ventana de tiempo en segundos durante la cual se cuentan las solicitudes.
ip_access_times: Diccionario que mapea direcciones IP a una lista de marcas de tiempo de las solicitudes.
Métodos
__init__(self, threshold, time_window): Inicializa los atributos de la clase.
log_request(self, ip_address): Registra una nueva solicitud desde una dirección IP específica y limpia las solicitudes antiguas.
cleanup_old_requests(self, ip_address, current_time): Elimina las solicitudes de una dirección IP que están fuera de la ventana de tiempo.
is_ddos(self, ip_address): Verifica si el número de solicitudes desde una dirección IP excede el umbral.
Simulación de Uso
En el bloque if __name__ == "__main__":, se crea una instancia de DDoSDetector con un umbral de 100 solicitudes por minuto. Luego, se simulan 105 solicitudes desde una dirección IP específica (test_ip). Si se detecta un posible ataque DDoS, se imprime un mensaje de alerta.

Manual de Uso
Ejecuta el archivo main.py:

La aplicación simulará solicitudes desde una dirección IP y detectará si se produce un posible ataque DDoS.

Puedes modificar los parámetros threshold y time_window en el archivo main.py para ajustar la sensibilidad del detector según tus necesidades.

Ejemplo de Uso
En este ejemplo, se crea un detector con un umbral de 100 solicitudes por minuto. Luego, se simulan 105 solicitudes desde la dirección IP 192.168.1.1. Si se detecta un posible ataque DDoS, se imprime un mensaje de alerta.

Contribuciones
Si deseas contribuir a este proyecto, por favor sigue los siguientes pasos:

Haz un fork del repositorio.
Crea una nueva rama (git checkout -b feature/nueva-funcionalidad).
Realiza tus cambios y haz commit (git commit -am 'Añadir nueva funcionalidad').
Sube tus cambios a tu fork (git push origin feature/nueva-funcionalidad).
Abre un Pull Request en este repositorio.
Licencia
Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.