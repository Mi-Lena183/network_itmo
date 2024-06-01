### Код для анализатора SYN Flood атаки с использованием библиотеки Scapy


from scapy.all import *
import threading
import time

# Функция для захвата и анализа пакетов
def packet_sniffer():
    def detect_syn_flood(packet):
        # Проверка на наличие SYN-флага
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            src_ip = packet[IP].src
            # Добавление IP в словарь или увеличение счетчика
            if src_ip in syn_count:
                syn_count[src_ip] += 1
            else:
                syn_count[src_ip] = 1
            
            # Вывод предупреждения при превышении порога
            if syn_count[src_ip] > SYN_FLOOD_THRESHOLD:
                print(f"[ALERT] Possible SYN Flood attack from {src_ip}")
    
    # Запуск захвата пакетов
    sniff(prn=detect_syn_flood, filter="tcp", store=0)

# Функция для генерации SYN Flood пакетов
def generate_syn_flood(target_ip, target_port, duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        send(IP(src=RandIP(), dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S"), verbose=0)

# Порог для обнаружения SYN Flood атаки
SYN_FLOOD_THRESHOLD = 100

# Словарь для хранения количества SYN пакетов от каждого IP
syn_count = {}

if __name__ == "__main__":
    # Запуск снифера в отдельном потоке
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()

    # Генерация SYN Flood для тестирования
    target_ip = "192.168.1.1"
    target_port = 80
    duration = 10  # Длительность генерации в секундах
    generate_syn_flood(target_ip, target_port, duration)

    # Ожидание завершения работы снифера
    sniffer_thread.join()





### Документация

#### Описание приложения

Приложение состоит из двух основных компонентов:
1. Анализатор сетевых пакетов для выявления атак типа SYN Flood.
2. Генератор SYN пакетов для тестирования анализатора.

Анализатор использует библиотеку Scapy для захвата и анализа пакетов в реальном времени. Он проверяет каждый TCP-пакет на наличие SYN-флага и ведет учет количества таких пакетов, отправленных с каждого IP-адреса. Если количество пакетов с одного IP превышает заданный порог, выводится предупреждение об обнаруженной атаке.

Генератор SYN пакетов позволяет сгенерировать большое количество пакетов с SYN-флагом, имитируя атаку SYN Flood для проверки работоспособности анализатора.

#### Алгоритм работы (PlantUML)



@startuml
actor User
participant "Packet Sniffer" as Sniffer
participant "SYN Flood Generator" as Generator

User -> Sniffer: Запуск анализатора
activate Sniffer
Sniffer -> Sniffer: Захват пакетов

User -> Generator: Запуск генератора
activate Generator
Generator -> Generator: Генерация SYN пакетов

Sniffer -> Sniffer: Анализ пакетов
Sniffer -> User: Вывод предупреждений (если обнаружена атака)

deactivate Generator
deactivate Sniffer
@enduml




#### Функциональные требования

1. Приложение должно захватывать TCP пакеты в реальном времени.
2. Приложение должно анализировать захваченные пакеты и выявлять SYN Flood атаки.
3. Приложение должно выводить предупреждение на консоль при обнаружении атаки.
4. Приложение должно генерировать SYN пакеты для тестирования.

#### Нефункциональные требования

1. Приложение должно быть написано на Python с использованием библиотеки Scapy.
2. Приложение должно работать в многопоточном режиме.
3. Приложение должно быть устойчиво к ошибкам и продолжать работу при возникновении исключений.
4. Приложение должно иметь возможность задавать порог для обнаружения атак.




   



