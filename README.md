# TriplAdvisor - HackMyVM (Easy)
 
![Tripladvisor.png](Tripladvisor.png)

## Übersicht

*   **VM:** TriplAdvisor
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Tripladvisor)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 14. August 2024
*   **Original-Writeup:** https://alientec1908.github.io/Tripladvisor_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "TriplAdvisor"-Challenge war die Erlangung von User- und System-Rechten auf einer Windows Server 2008 R2 Maschine. Der Weg begann mit der Enumeration eines Webservers (Port 8080), der eine WordPress-Installation (`/wordpress/`) mit einem verwundbaren Plugin ("editor" v1.1) hostete. Eine Local File Inclusion (LFI)-Schwachstelle in diesem Plugin wurde mittels Log Poisoning ausgenutzt, um Remote Code Execution (RCE) zu erlangen und eine Meterpreter-Session als Benutzer `websvc` zu etablieren. Die User-Flag wurde auf dessen Desktop gefunden. Die Privilegieneskalation zu `NT AUTHORITY\SYSTEM` erfolgte durch Ausnutzung einer bekannten Schwachstelle (MS16-075 "Reflection Juicy Potato") mittels Metasploit. Die Root-Flag (System-Flag) wurde auf dem Desktop des Administrators gefunden. Zusätzlich wurden NTLM-Hashes aus der SAM-Datenbank extrahiert, was Pass-the-Hash-Angriffe ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nmap`
*   `smbclient`
*   `rpcclient`
*   `lookupsid.py` (Impacket)
*   `gobuster`
*   `curl`
*   `wpscan`
*   `wfuzz`
*   `msfvenom`
*   `msfconsole` (Metasploit Framework)
*   `meterpreter` (insbesondere `hashdump`, `shell`)
*   Standard Windows-Befehle (`whoami /priv`, `dir`, `type`)
*   Standard Linux-Befehle (`cat`, `ls`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "TriplAdvisor" gliederte sich in folgende Phasen:

1.  **Reconnaissance & SMB-Analyse:**
    *   IP-Findung mit `arp-scan` (mehrere IPs im Log, Hauptziel `192.168.2.119`).
    *   Eintrag von `Tripladvisor` (später `tripladvisor:8080`) in lokale `/etc/hosts`.
    *   `nmap`-Scan auf verschiedene IPs. `192.168.2.119` zeigte Port 445 (SMB) und Port 8080 (HTTP-Proxy/Webserver) als offen.
    *   Untersuchung von SMB auf anderen IPs (`.116`, `.117`) zeigte, dass SMB Signing nicht erzwungen wurde. RPC Null-Session war möglich, aber SID-Enumeration via `lookupsid.py` scheiterte.

2.  **Web Enumeration & LFI (Port 8080):**
    *   `gobuster` auf `http://Tripladvisor:8080` fand eine WordPress-Installation unter `/wordpress/`.
    *   WordPress REST API (`/wp-json/wp/v2/users`) offenbarte den Benutzer `admin`.
    *   `wpscan` bestätigte den Benutzer `admin` und identifizierte das Plugin "editor" Version 1.1.
    *   Ein `wpscan`-Passwort-Bruteforce auf `admin` war erfolglos.
    *   Recherche nach Exploits für "editor" v1.1 ergab eine LFI-Schwachstelle (z.B. `exploit/44340`).
    *   `wfuzz` mit LFI-Payloads auf `ajax_shortcode_pattern.php` (Teil des "editor"-Plugins) fand lesbare Logdateien (`\xampp\apache\logs\access.log`, `error.log`) und `C:\WINDOWS\win.ini`.
    *   Auslesen der `access.log` via LFI bestätigte die WordPress-Version 5.1.19.

3.  **Initial Access (LFI zu RCE zu Meterpreter als `websvc`):**
    *   Log Poisoning: Ein PHP-Payload (`<?php system($_GET['cmd']); ?>` oder komplexer) wurde via User-Agent (`curl -A "..."`) in die `access.log` geschrieben.
    *   Ausführung des Payloads durch Aufruf der `access.log` über die LFI-Schwachstelle, was RCE bestätigte (Ausgabe von `dir`).
    *   Generierung eines PowerShell Meterpreter Reverse TCP Payloads (`windows/x64/meterpreter/reverse_tcp`) mit `msfvenom`.
    *   Einrichten eines Metasploit `multi/handler`-Listeners.
    *   Einschleusen und Auslösen des PowerShell-Payloads (Base64-kodiert) via LFI und Log Poisoning (eingebettet in PHP-Tags, gesendet als User-Agent).
    *   Erfolgreiche Meterpreter-Session als Benutzer `TRIPLADVISOR\websvc`.
    *   User-Flag `4159a2b3a38697518722695cbb09ee46` in `C:\Users\websvc\Desktop\user.txt` gelesen.

4.  **Privilege Escalation (von `websvc` zu `NT AUTHORITY\SYSTEM`):**
    *   `whoami /priv` in einer `cmd.exe`-Shell (via Meterpreter `shell`) zeigte Standardprivilegien für `websvc`.
    *   Metasploit `post/multi/recon/local_exploit_suggester` fand mehrere potenzielle Exploits für Windows Server 2008 R2.
    *   Auswahl und Ausführung des Exploits `exploit/windows/local/ms16_075_reflection_juicy`.
    *   Erfolgreiche Ausführung des Exploits führte zu einer neuen Meterpreter-Session mit `NT AUTHORITY\SYSTEM`-Rechten.
    *   Root-Flag (System-Flag) `5b38df6802c305e752c8f02358721acc` in `C:\Users\Administrator\Desktop\root.txt` gelesen.
    *   Zusätzlich: `hashdump` (Meterpreter) extrahierte NTLM-Passwort-Hashes (Administrator, Guest, websvc), was Pass-the-Hash-Angriffe (demonstriert mit `smbclient`) ermöglichte.

## Wichtige Schwachstellen und Konzepte

*   **Veraltetes WordPress-Plugin ("editor" v1.1):** Anfällig für Local File Inclusion (LFI).
*   **Log Poisoning:** Einschleusen von schädlichem Code (PHP/PowerShell) in Logdateien und anschließende Ausführung über LFI zur Erlangung von RCE.
*   **Veraltetes Betriebssystem (Windows Server 2008 R2):** Anfällig für bekannte Privilege-Escalation-Exploits (hier MS16-075).
*   **WordPress REST API User Enumeration:** Offenlegung von Benutzernamen (`admin`).
*   **SMB Message Signing nicht erzwungen (auf anderen Hosts):** Potenzial für SMB-Relay-Angriffe.
*   **Credential Dumping (NTLM Hashes):** Extraktion von Passwort-Hashes aus der SAM-Datenbank ermöglichte Pass-the-Hash.
*   **XAMPP-Umgebung:** Deutet oft auf weniger gehärtete Konfigurationen hin.

## Flags

*   **User Flag (`C:\Users\websvc\Desktop\user.txt`):** `4159a2b3a38697518722695cbb09ee46`
*   **Root Flag (`C:\Users\Administrator\Desktop\root.txt`):** `5b38df6802c305e752c8f02358721acc`

## Tags

`HackMyVM`, `TriplAdvisor`, `Easy`, `Windows`, `WordPress`, `LFI`, `Log Poisoning`, `RCE`, `Metasploit`, `MS16-075`, `Juicy Potato`, `Privilege Escalation`, `SMB`, `Hashdump`, `Pass-the-Hash`, `XAMPP`
