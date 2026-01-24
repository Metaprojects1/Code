# Guida PX4 su Windows (WSL2 + Ubuntu) — build e simulazione

Questa guida spiega come **compilare PX4-Autopilot su Windows 10/11** usando l’approccio **raccomandato**: **WSL2 + Ubuntu**.

Riferimenti ufficiali:
- Dev env Windows WSL: https://docs.px4.io/main/en/dev_setup/dev_env_windows_wsl
- Building PX4: https://docs.px4.io/main/en/dev_setup/building_px4

---

## 0) Perché WSL2 (consigliato)

Con WSL2 puoi:
- compilare PX4 come su Ubuntu (piattaforma più testata),
- usare VS Code su Windows con integrazione Remote-WSL,
- usare QGroundControl in Linux dentro WSL per la simulazione (connessione semplice).

Nota importante:
- **Per flashare una flight controller via USB** è consigliato usare **QGroundControl su Windows**, perché WSL2 non ha accesso USB/seriale “nativo”.

---

## 1) Installa WSL2 + Ubuntu

1. Abilita la virtualizzazione nel BIOS/UEFI (Intel VT-x / AMD-V).
2. Apri **cmd.exe** o **Windows Terminal** come **Amministratore**.
3. Installa WSL2 con Ubuntu:

### Opzione A — installazione standard (Ubuntu di default)
```bat
wsl --install
```

### Opzione B — scegli la distro esplicitamente (consigliato Ubuntu 22.04)
```bat
wsl --install -d Ubuntu-22.04
```

> Se ti serve Gazebo Classic, nella doc PX4 spesso viene indicato Ubuntu 20.04:
```bat
wsl --install -d Ubuntu-20.04
```

4. Alla prima apertura, Ubuntu ti chiederà **username e password**.

---

## 2) Avvia WSL e lavora nel filesystem Linux

Apri una shell WSL:
```bat
wsl
```

Oppure specifica la distro:
```bat
wsl -d Ubuntu-22.04
```

> Consiglio: lavora nella home Linux (`~`) e **non** in `/mnt/c/...` per evitare lentezze e problemi di permessi.

---

## 3) Clona PX4 e installa la toolchain (in WSL)

Nel terminale WSL:

```bash
cd ~
git clone https://github.com/PX4/PX4-Autopilot.git --recursive
bash ./PX4-Autopilot/Tools/setup/ubuntu.sh
```

A fine script, chiudi WSL e riavvialo:

Dentro WSL:
```bash
exit
```

Da Windows:
```bat
wsl --shutdown
wsl
```

---

## 4) Prima build di test (SITL)

Nel terminale WSL:

```bash
cd ~/PX4-Autopilot
make px4_sitl
```

### Avviare simulazione con Gazebo (nuovo)
```bash
make px4_sitl gz_x500
```

### Avviare simulazione con Gazebo Classic
```bash
make px4_sitl gazebo-classic
```

---

## 5) QGroundControl: WSL vs Windows

### Opzione A — QGroundControl dentro WSL (comodo per simulazione)
- Scarica la AppImage di QGC (Linux)
- Rendila eseguibile e avviala:

```bash
chmod +x QGroundControl.AppImage
./QGroundControl.AppImage
```

Vantaggio: spesso si connette facilmente alla simulazione.  
Limite: **non** è la strada migliore per flash firmware su hardware via USB.

### Opzione B — QGroundControl su Windows (necessario per flash hardware)
Per collegare QGC Windows alla simulazione che gira in WSL:

1. In WSL, trova l’IP (di solito su `eth0`):
```bash
ip addr | grep eth0
```

2. In QGC su Windows: **Application Settings → Comm Links**
   - Aggiungi un **UDP Link**
   - Host: IP di WSL
   - Porta: **18570**

Nota: l’IP di WSL può cambiare a ogni riavvio → potrebbe servire aggiornare il link.

---

## 6) Build per hardware Pixhawk / NuttX

Esempio (Pixhawk 4 / FMUv5):

```bash
cd ~/PX4-Autopilot
make px4_fmu-v5
```

Per vedere tutti i target disponibili:
```bash
make list_config_targets
```

### Flash firmware su board
- Metodo consigliato: **QGroundControl su Windows** → *Vehicle Setup → Firmware*.

> Alternativa avanzata (non necessaria per iniziare): USB forwarding con usbipd-win (vedi doc PX4 Windows WSL).

---

## 7) VS Code su Windows con Remote-WSL (consigliato)

1. Installa VS Code su Windows.
2. Installa l’estensione **Remote - WSL**.
3. Da WSL, apri la cartella del repo:

```bash
cd ~/PX4-Autopilot
code .
```

Così lavori direttamente nel contesto Linux (più stabile e veloce per build).

---

## Troubleshooting rapido

### Submodule mancanti
Se hai clonato senza `--recursive`:

```bash
cd ~/PX4-Autopilot
git submodule update --init --recursive
```

### Pulizia build
Se la build fa cose strane:

```bash
cd ~/PX4-Autopilot
make distclean
```

---

## Cygwin (sconsigliato)
Esiste una toolchain Windows via Cygwin, ma è community-supported e la doc PX4 avverte che **non funziona con PX4 v1.12+** per problemi di packaging.  
Meglio WSL2.

Riferimento: https://docs.px4.io/main/en/dev_setup/dev_env_windows_cygwin
