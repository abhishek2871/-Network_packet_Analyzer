#  Network_packet_Analyzer

The Network Packet Analyzer is a Python-based tool designed to capture, inspect, and analyze network traffic in real time. Using Scapy for packet sniffing and Tkinter for a user-friendly GUI, the analyzer provides a detailed view of network communication happening on your system.

---

## 🔍 Network Sniffer (Python + Tkinter + Scapy)

A Windows-compatible GUI-based Network Packet Sniffer built using Python, Tkinter, and Scapy.
This tool allows users to capture, inspect, and analyze live network packets in real time through an easy-to-use graphical interface.

---

## 🚀 Features

### ✅ User-Friendly GUI

  Simple and clean Tkinter interface — no command line required.

### ✅ Real-Time Packet Capture

  Displays:
  
  Source IP
  
  Destination IP
  
  Protocol (TCP/UDP/ICMP/Other)

  Source Port

  Destination Port

  Packet Size

### ✅ Interface Auto-Detection

Automatically loads available network interfaces for sniffing.

### ✅ Start & Stop Controls

Single-click start/stop makes network monitoring easy.

### ✅ Threaded Sniffing

Sniffing runs in a separate thread so the GUI stays responsive.

### ✅ Windows Compatible

Designed to run smoothly on Windows machines.

---

## 🛠 Technologies Used

  Python
  
  Tkinter (GUI)
  
  Scapy (Packet Sniffing)
  
  Threading

  ---

## 🔧 How to Run

### 📌 1. Install Dependencies

       sudo apt update
       
      pip install scapy
      
      pip install tkintertable   # only needed if missing (Tkinter is usually preinstalled)

### 📌 2. Run the Application

    python network-sniffer.py

 ---   

✅ 3. Download or Save the Script

     git clone 

---

    cd Network_packet_Analyzer

---

     chnod 777 network-sniffer.py
---

     python3 network-sniffer.py

## 📁 Project Structure
  
  📦 Network-Sniffer
  
   ┣ 📜 network-sniffer.py
  
   ┗ 📜 README.md

---

## 🧠 How It Works

  Select an interface from the dropdown.
  
  Click Start Sniffing.
  
  Scapy captures packets and sends them to the GUI callback.
  
  Packet details such as IPs, ports, protocol, and length appear in real time.
  
  Click Stop Sniffing anytime to end capture.

---

## 🎯 Use Cases
  Learning network packet structure
  
  Practicing cybersecurity & network analysis
  
  Educational demonstrations

  SOC / VAPT beginner-friendly training tool

---

## 🛡 Disclaimer

  This tool is intended ONLY for educational and ethical purposes.
  
  Use it only on networks you own or have permission to analyze.

## 📢 Contributions

  Pull requests are welcome!
  
  Feel free to raise Issues or suggest improvements.

