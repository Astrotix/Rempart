# 📊 Logs de Trafic du Connecteur

## Comment voir les logs de trafic

Quand tu accèdes à `192.168.75.130` depuis ton PC, le trafic passe par le connecteur. Voici comment voir ces logs.

---

## Sur le serveur du connecteur

### Option 1 : Journalctl (recommandé - systemd)

```bash
# Voir les logs en temps réel
sudo journalctl -k -f | grep ZTNA-CONNECTOR

# Ou avec plus de contexte
sudo journalctl -k -f | grep -A 2 -B 2 ZTNA-CONNECTOR
```

### Option 2 : /var/log/kern.log

```bash
# Voir les logs en temps réel
sudo tail -f /var/log/kern.log | grep ZTNA-CONNECTOR

# Ou avec plus de contexte
sudo tail -f /var/log/kern.log | grep -A 2 -B 2 ZTNA-CONNECTOR
```

### Option 3 : dmesg

```bash
# Voir les logs en temps réel
sudo dmesg -w | grep ZTNA-CONNECTOR
```

### Option 4 : Logs du connecteur (si monitoring activé)

Si le connecteur a le monitoring activé, tu verras aussi les logs directement dans la sortie du connecteur :

```bash
# Les logs apparaîtront avec le préfixe "🔍 TRAFIC:"
[Connector] 🔍 TRAFIC: ...
```

---

## Format des logs

Les logs iptables montrent :
- **Source IP** : L'IP du client (100.64.x.x)
- **Destination IP** : L'IP du réseau interne (192.168.75.130)
- **Protocole** : TCP, UDP, ICMP, etc.
- **Ports** : Port source et destination

Exemple de log :
```
ZTNA-CONNECTOR[abc12345]: IN=wg-connector OUT=eth0 SRC=100.64.0.6 DST=192.168.75.130 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=12345 PROTO=TCP SPT=54321 DPT=22
```

---

## Commandes utiles

### Voir uniquement les connexions vers 192.168.75.130

```bash
sudo journalctl -k -f | grep "ZTNA-CONNECTOR.*192.168.75.130"
```

### Voir uniquement le trafic TCP (SSH, HTTP, etc.)

```bash
sudo journalctl -k -f | grep "ZTNA-CONNECTOR.*PROTO=TCP"
```

### Compter le nombre de connexions

```bash
sudo journalctl -k | grep "ZTNA-CONNECTOR" | wc -l
```

### Voir les dernières connexions

```bash
sudo journalctl -k | grep "ZTNA-CONNECTOR" | tail -20
```

---

## Désactiver les logs (si trop verbeux)

Si les logs sont trop nombreux, tu peux désactiver les règles iptables LOG :

```bash
# Lister les règles LOG
sudo iptables -L FORWARD -n -v | grep LOG

# Supprimer les règles LOG (remplace le numéro de ligne)
sudo iptables -D FORWARD <NUMERO_LIGNE>
```

---

## Alternative : tcpdump sur l'interface WireGuard

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
```

---

## Alternative : wireshark/tshark

Pour une analyse plus détaillée :

```bash
# Installer tshark
sudo apt install -y tshark

# Capturer le trafic
sudo tshark -i wg-connector -f "dst 192.168.75.130" -w capture.pcap

# Analyser le fichier capturé
tshark -r capture.pcap
```

---

## Vérifier que les règles iptables LOG sont actives

```bash
# Voir toutes les règles FORWARD avec LOG
sudo iptables -L FORWARD -n -v | grep LOG

# Tu devrais voir des règles comme :
# LOG  all  --  100.64.0.0/16  192.168.75.0/24  LOG flags 0 level 4 prefix "ZTNA-CONNECTOR[...]: "
```

---

## Exemple de session complète

```bash
# Terminal 1 : Lancer le connecteur
sudo ./ztna-connector --token ... --control-plane ... --networks 192.168.75.0/24

# Terminal 2 : Surveiller les logs
sudo journalctl -k -f | grep ZTNA-CONNECTOR

# Terminal 3 : Depuis ton PC Windows, tester
ping 192.168.75.130
ssh user@192.168.75.130

# Tu verras les logs apparaître dans Terminal 2
```

---

## Troubleshooting

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
