# report tcp block
## 과제
Out of path 환경에서 TCP Packet Injection(RST, FIN 플래그를 포함한)를 이용하여 사이트를 차단하는 프로그램을 작성하라.

## 실행
```
syntax : tcp-block <interface> <pattern>
sample : tcp-block wlan0 "Host: test.gilgil.net"
```

## 상세
- Out of path의 대표격인 pcap library를 이용하여 패킷을 수신한다.

- 수신된 패킷의 TCP Data 영역에 pattern이 검색되는 경우 차단 패킷을 양쪽으로 송신한다.

- 정방향(forward)은 RST flag를 포함한 패킷을 송신한다(자신의 머신에 wget이나 웹브라우저를 이용해서 테스트).

- 역방향(backward)는 FIN flag 및 "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n"의 TCP Data를 포함한 패킷을 송신한다(자신의 머신에 tcp server(ts)를 띄워 놓고 같은 네트워크 대역의 다른 호스트(스마트폰)에서 자신의 머신으로 HTTP 연결을 시도해서 테스트).

## 결과
### TEST 80
#### Forward Test
<img src = "https://user-images.githubusercontent.com/76524512/144200530-c37dae4f-3b95-49e6-8f01-72b43367a33b.gif">

#### Backward Test
<img src = "https://user-images.githubusercontent.com/76524512/144200277-d4410ed1-6871-49f9-bb5d-477ebe8a2b09.gif">
<img src = "https://user-images.githubusercontent.com/76524512/144200417-985fdc01-c82b-49a1-9f2b-ecb8fa939aad.gif)">


