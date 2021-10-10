# arp-spoof
## 과제
arp spoofing 프로그램을 구현하라.

## 실행
```
syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```

## 상세
- 이전 과제(send-arp)를 다 수행하고 나서 이번 과제를 할 것.

- "arp-spoofing.ppt"의 내용을 숙지할 것.

- 코드에 victim, gateway라는 용어를 사용하지 말고 sender, target(혹은 receiver)라는 단어를 사용할 것.

- sender에서 보내는 spoofed IP packet을 attacker가 수신하면 이를 relay하는 것 코드를 구현할 것.

- sender에서 infect가 풀리는(recover가 되는) 시점을 정확히 파악하여 재감염시키는 코드를 구현할 것.

- (sender, target) flow를 여러개 처리할 수 있도록 코드를 구현할 것.

- 가능하다면 주기적으로 ARP infect packet을 송신하는 기능도 구현해 볼 것.

- attacker, sender, target은 물리적으로 다른 머신이어야 함. 가상환경에서 Guest OS가 attacker, Host OS가 sender가 되거나 하면 안됨.

- Vmware에서 Guest OS를 attacker로 사용할 때 sender로부터의 spoofed IP packet이 보이지 않을 경우 vmware_adapter_setting 문서를 참고할 것.

- VirtualBox에서 Guest OS를 attacker로 사용할 때 sender로부터의 spoofeed IP packet이 보이지 않은 경우 https://gilgil.gitlab.io/2021/09/29/1.html 문서를 참고할 것.

- Host OS의 네트워크를 사용하지 않고 별도의 USB 기반 네트워크 어댑터를 Guest OS에서 사용하는 것을 추천. 다이소에서 5000원으로 구매할 수 있음. - https://www.youtube.com/watch?v=f8baVYPM9Pc

## 코드리뷰
- resolving 2번 (보통은 4번으로 짤 가능성 높음)
- Thread 사용 (infect & relay)
- Ctrl+C로 종료 추가 : `signal(SIGINT, function pointer)`
- sleep 필요 (1초는 너무 김) (정상 패킷으로 덮어쓰이는거 방지)
- IP, MAC std::vertor, map, list 등을 이용해서 관리
- HOST ARP TABLE 처리 (변조될 가능성)
