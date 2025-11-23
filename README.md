# HW6_-modern_computer_networks-

### ICMP и DNS перехватчик для traceroute

Программа имитирует поведение traceroute, отображая текст трека в качестве промежуточных хопов.

#### Описание

При выполнении команды `traceroute trap.music` программа перехватывает ICMP и DNS пакеты и отвечает собственными сообщениями, создавая иллюзию маршрута через хосты с именами из трека.

#### Использование
```bash
sudo python3 interceptor.py eth0 eth1
```

Затем на клиентском узле:
```bash
traceroute trap.music
```


