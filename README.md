# Simple Python Port Scanner

A lightweight, multi-threaded port scanner written in Python. This tool can identify open TCP ports on a target host and perform basic banner grabbing to infer the service and version running on those ports.

This project is intended for educational purposes to demonstrate the fundamentals of network programming, socket communication, and multithreading in Python.

*Note: You would replace this with a real screenshot of the script's output.*

## Features

- **Fast Port Scanning:** Uses multithreading to scan multiple ports concurrently.
- **Flexible Port Selection:** Scan a single port, a comma-separated list, a range, or a combination.
- **Service & Version Detection:** Performs banner grabbing on open ports to identify running services (e.g., SSH, FTP, HTTP) and their versions.
- **Simple OS Inference:** Makes an educated guess about the underlying operating system based on service banners.
- **User-Friendly CLI:** Clean and simple command-line interface for easy use.
- **No External Dependencies:** Runs using only standard Python libraries.

## ⚠️ Disclaimer

This tool is for educational and ethical purposes only. **Do not use this script to scan networks or hosts that you do not have explicit, written permission to test.** Unauthorized port scanning is illegal in many jurisdictions and is a violation of most Internet Service Providers' terms of service. The user is responsible for any and all misuse of this script.

The creators of this script are not responsible for any damage or legal issues caused by its use.

## Requirements

- Python 3.6+

No external libraries are needed.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/hosseinghDev/simple_port_scanner.git
   ```
2. Navigate to the project directory:
   ```bash
   cd simple_port_scanner
   ```

## Usage

The script is run from the command line with the target as the primary argument.

```bash
python scanner.py <target> [options]
```

### **Arguments**

- `<target>` (**Required**): IP address or hostname of the target to scan.

### **Options**

- `-p`, `--ports`: Ports to scan. If omitted, common ports will be scanned by default.
  - Single port: `-p 80`
  - Comma-separated: `-p 80,443,8080`
  - Range: `-p 1-1024`
  - Combination: `-p 22,80,443,1000-1100`
- `-t`, `--threads`: Number of concurrent threads to use (default: `100`). Higher values increase speed but consume more resources.

---

## 📌 Examples

**1. Scan a target for common ports:**

```bash
python scanner.py scanme.nmap.org
```

**2. Scan a specific range of ports:**

```bash
python scanner.py 192.168.1.1 -p 1-200
```

**3. Scan a list of ports with increased thread count:**

```bash
python scanner.py example.com -p 21,22,80,443,3306 -t 200
```

---

## 🖥️ Example Output

```
============================================================
      Python Port Scanner with Service/OS Detection
============================================================
DISCLAIMER: This tool is for educational purposes only.
Scanning networks without permission is illegal and unethical.
------------------------------------------------------------
[*] Scanning Target: scanme.nmap.org (45.33.32.156)
[*] Scanning 17 port(s) with 100 threads.
------------------------------------------------------------
[+] Port 22    is OPEN
    Service:   SSH
    Version:   OpenSSH 6.6.1p1 (Protocol 2.0)
    OS Guess:  (Apple Mac OS X 10.12)
    Raw Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
------------------------------------------------------------
[+] Port 80    is OPEN
    Service:   HTTP/HTTPS
    Version:   Apache/2.4.7
    OS Guess:  (Ubuntu)
    Raw Banner:
------------------------------------------------------------
[*] Scan Completed in: 0:00:02.123456
============================================================
```

---

## ⚙️ How It Works

- **Argument Parsing**: Handled via `argparse` for clean CLI support.
- **Hostname Resolution**: Uses `socket.gethostbyname()` to resolve targets.
- **Port Queueing**: Ports are placed in a thread-safe `queue.Queue`.
- **Multithreading**: Threads are created to process ports concurrently.
- **Connection Logic**: Each port is scanned using `socket.connect_ex()`.
- **Banner Grabbing**: Attempts to read 1024 bytes from open ports.
- **Banner Analysis**: Uses regex and keyword matching to guess services and OS.
- **Thread-Safe Output**: Uses `threading.Lock` to keep console output clean.

---

## ⚠️ Limitations

- **OS Detection**: Simple inference from banners; not as accurate as tools like Nmap.
- **Firewalls/IDS**: Can be easily detected or blocked.
- **No SSL/TLS Handling**: Cannot perform encrypted handshakes (e.g., HTTPS).

> For more accurate and stealthy scanning, consider using [Nmap](https://nmap.org/).

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!\
Feel free to open an issue or submit a pull request.

---

## 📄 License

This project is licensed under the **MIT License**.

