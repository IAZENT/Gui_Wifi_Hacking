# WiFi Security Testing Tool (GUI-Based)
![image](https://github.com/user-attachments/assets/8ef47515-7ec3-4fa9-9d56-b0a9fd8d0688)

🚀 **WiFi Security Testing Tool** is a GUI-based penetration testing tool for wireless networks, allowing security professionals to analyze and test WiFi vulnerabilities.

⚠️ **Disclaimer:** This tool is for **educational and legal security testing purposes only**. Unauthorized access to networks you do not own is illegal.

---

## 🔥 Features
- **Network Scanning**: Detects nearby wireless networks.
- **Monitor Mode Control**: Enables/disables monitor mode on the selected interface.
- **Handshake Capture**: Captures WPA2 handshakes for password cracking.
- **Deauthentication Attack**: Sends deauth packets to force clients to reconnect.
- **WPS Attacks**: Uses `reaver`, `bully`, and `pixiewps` for WPS brute-force attacks.
- **Handshake Cracking**: Supports **RockYou.txt** and custom wordlists.
- **Custom Wordlist Generator**: Uses `crunch` to create tailored password lists.
- **GUI-Based**: Built with **Tkinter** for ease of use.
- **Progress Tracking**: Displays capture status, attack progress, and logs.

---

## 🛠️ Installation

### **1️⃣ Install Dependencies**
Run the following command:
```bash
pip install -r requirements.txt
