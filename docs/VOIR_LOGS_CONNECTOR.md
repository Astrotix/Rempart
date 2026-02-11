# 📋 Guide : Voir les Logs du Connecteur

## 1. Logs du Processus du Connecteur

### Si le connecteur tourne en mode interactif (terminal)

Si tu as lancé le connecteur avec `sudo ./ztna-connector ...`, les logs s'affichent directement dans le terminal :

```bash
[Connector] 2026/02/11 01:05:27 main.go:35: ==============================================
[Connector] 2026/02/11 01:05:27 main.go:36:   ZTNA Sovereign - Site Connector
[Connector] 2026/02/11 01:05:27 main.go:37:   Control Plane: http://176.136.202.205:8080
[Connector] 2026/02/11 01:05:27 main.go:38:   Networks: 192.168.75.0/24
[Connector] 2026/02/11 01:05:27 main.go:39: ==============================================
[Connector] 2026/02/11 01:05:27 service.go:58: Starting site connector...
[Connector] 2026/02/11 01:05:27 service.go:113: Cles existantes chargees depuis le fichier
[Connector] 2026/02/11 01:05:27 service.go:154: Registered with Control Plane as connector abc123...
```

### Si le connecteur tourne en arrière-plan (systemd ou nohup)

#### Option A : Voir les logs systemd

Si tu as créé un service systemd :

```bash
# Voir les logs en temps réel
sudo journalctl -u ztna-connector -f

# Voir les dernières 100 lignes
sudo journalctl -u ztna-connector -n 100

# Voir les logs depuis aujourd'hui
sudo journalctl -u ztna-connector --since today
```

#### Option B : Voir les logs nohup

Si tu as lancé avec `nohup` :

```bash
# Voir le fichier nohup.out
tail -f nohup.out

# Ou si tu as redirigé vers un fichier
tail -f /var/log/ztna-connector.log
```

#### Option C : Voir les logs du processus

```bash
# Trouver le PID du connecteur
ps aux | grep ztna-connector

# Voir les logs via journalctl avec le PID
sudo journalctl _PID=<PID> -f
```

---

## 2. Logs de Trafic Réseau (iptables)

Quand tu accèdes à `192.168.75.130` depuis ton PC, le trafic passe par le connecteur. Voici comment voir ces logs.

### Option 1 : Journalctl (recommandé)

```bash
# Voir les logs de trafic en temps réel
sudo journalctl -k -f | grep ZTNA-CONNECTOR

# Avec plus de contexte (2 lignes avant/après)
sudo journalctl -k -f | grep -A 2 -B 2 ZTNA-CONNECTOR

# Filtrer uniquement le trafic vers 192.168.75.130
sudo journalctl -k -f | grep "ZTNA-CONNECTOR.*192.168.75.130"

# Voir uniquement le trafic TCP (SSH, HTTP, etc.)
sudo journalctl -k -f | grep "ZTNA-CONNECTOR.*PROTO=TCP"
```

### Option 2 : /var/log/kern.log

```bash
# Voir les logs en temps réel
sudo tail -f /var/log/kern.log | grep ZTNA-CONNECTOR

# Avec plus de contexte
sudo tail -f /var/log/kern.log | grep -A 2 -B 2 ZTNA-CONNECTOR
```

### Option 3 : dmesg

```bash
# Voir les logs en temps réel
sudo dmesg -w | grep ZTNA-CONNECTOR
```

### Format des logs de trafic

Les logs iptables montrent :
- **Source IP** : L'IP du client (100.64.x.x)
- **Destination IP** : L'IP du réseau interne (192.168.75.130)
- **Protocole** : TCP, UDP, ICMP, etc.
- **Ports** : Port source et destination

Exemple :
```
ZTNA-CONNECTOR[abc12345]: IN=wg-connector OUT=eth0 SRC=100.64.0.6 DST=192.168.75.130 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=12345 PROTO=TCP SPT=54321 DPT=22
```

---

## 3. Logs WireGuard

### Voir les statistiques WireGuard

```bash
# Voir les statistiques du tunnel
sudo wg show wg-connector

# Voir les statistiques en temps réel (toutes les 2 secondes)
watch -n 2 sudo wg show wg-connector
```

### Voir les logs WireGuard système

```bash
# Logs WireGuard via dmesg
sudo dmesg | grep -i wireguard

# Logs WireGuard via journalctl
sudo journalctl -k | grep -i wireguard
```

---

## 4. Logs du Monitoring Intégré

Si le connecteur a le monitoring activé, tu verras aussi les logs directement dans la sortie du connecteur :

```bash
# Les logs apparaîtront avec le préfixe "🔍 TRAFIC:"
[Connector] 🔍 TRAFIC: ZTNA-CONNECTOR[abc12345]: IN=wg-connector OUT=eth0 SRC=100.64.0.6 DST=192.168.75.130 ...
```

---

## 5. Commandes Utiles

### Voir toutes les connexions récentes

```bash
sudo journalctl -k | grep "ZTNA-CONNECTOR" | tail -50
```

### Compter le nombre de connexions

```bash
sudo journalctl -k | grep "ZTNA-CONNECTOR" | wc -l
```

### Voir uniquement les connexions vers une IP spécifique

```bash
sudo journalctl -k | grep "ZTNA-CONNECTOR.*192.168.75.130"
```

### Voir uniquement les connexions TCP (SSH, HTTP, etc.)

```bash
sudo journalctl -k | grep "ZTNA-CONNECTOR.*PROTO=TCP"
```

### Voir les logs depuis une heure spécifique

```bash
sudo journalctl -k --since "1 hour ago" | grep ZTNA-CONNECTOR
```

---

## 6. Créer un Service Systemd (Recommandé)

Pour avoir des logs propres et persistants, crée un service systemd :

```bash
# Créer le fichier de service
sudo nano /etc/systemd/system/ztna-connector.service
```

Contenu du fichier :

```ini
[Unit]
Description=ZTNA Sovereign Site Connector
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ztna-connector \
  --token <TON_TOKEN> \
  --control-plane http://176.136.202.205:8080 \
  --networks 192.168.75.0/24
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Puis :

```bash
# Recharger systemd
sudo systemctl daemon-reload

# Démarrer le service
sudo systemctl start ztna-connector

# Activer au démarrage
sudo systemctl enable ztna-connector

# Voir les logs
sudo journalctl -u ztna-connector -f
```

---

## 7. Alternative : tcpdump pour Analyse Détaillée

Pour voir le trafic brut sur l'interface WireGuard :

```bash
# Installer tcpdump si nécessaire
sudo apt install -y tcpdump

# Capturer le trafic sur l'interface WireGuard
sudo tcpdump -i wg-connector -n -v

# Filtrer uniquement le trafic vers 192.168.75.130
sudo tcpdump -i wg-connector -n -v "dst 192.168.75.130"

# Voir les connexions TCP
sudo tcpdump -i wg-connector -n -v "tcp and dst 192.168.75.130"

# Sauvegarder dans un fichier
sudo tcpdump -i wg-connector -w /tmp/capture.pcap
```

---

## 8. Vérifier que les Règles iptables LOG sont Actives

```bash
# Voir toutes les règles FORWARD avec LOG
sudo iptables -L FORWARD -n -v | grep LOG

# Tu devrais voir des règles comme :
# LOG  all  --  100.64.0.0/16  192.168.75.0/24  LOG flags 0 level 4 prefix "ZTNA-CONNECTOR[...]: "
```

---

## 9. Exemple de Session Complète

```bash
# Terminal 1 : Lancer le connecteur
sudo ./ztna-connector \
  --token <TOKEN> \
  --control-plane http://176.136.202.205:8080 \
  --networks 192.168.75.0/24

# Terminal 2 : Surveiller les logs de trafic
sudo journalctl -k -f | grep ZTNA-CONNECTOR

# Terminal 3 : Depuis ton PC Windows, tester
ping 192.168.75.130
ssh user@192.168.75.130

# Tu verras les logs apparaître dans Terminal 2
```

---

## 10. Troubleshooting

### Pas de logs visibles

1. Vérifie que les règles iptables LOG sont présentes :
   ```bash
   sudo iptables -L FORWARD -n -v | grep LOG
   ```

2. Vérifie que le trafic passe bien par le connecteur :
   ```bash
   # Sur le connecteur, voir les statistiques WireGuard
   sudo wg show wg-connector
   ```

3. Vérifie que le forwarding IP est activé :
   ```bash
   sysctl net.ipv4.ip_forward
   # Doit retourner : net.ipv4.ip_forward = 1
   ```

### Logs trop nombreux

Les logs iptables peuvent être très verbeux. Tu peux :
- Filtrer par destination : `grep "DST=192.168.75.130"`
- Filtrer par protocole : `grep "PROTO=TCP"`
- Réduire le niveau de log (modifier `--log-level 4` à `--log-level 6`)
