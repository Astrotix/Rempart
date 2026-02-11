# 🔍 Debug : Pas de Logs de Trafic

Si tu ne vois rien dans les logs de trafic, voici comment diagnostiquer le problème.

## 1. Vérifier que les règles iptables LOG sont présentes

```bash
# Voir toutes les règles FORWARD avec LOG
sudo iptables -L FORWARD -n -v | grep LOG

# Tu devrais voir des règles comme :
# LOG  all  --  100.64.0.0/16  192.168.75.0/24  LOG flags 0 level 4 prefix "ZTNA-CONNECTOR[...]: "
```

Si tu ne vois rien, les règles LOG ne sont pas actives.

## 2. Vérifier que le trafic passe par WireGuard

```bash
# Voir les statistiques WireGuard
sudo wg show wg-connector

# Tu devrais voir des "transfer" (bytes reçus/envoyés) qui augmentent
# Si c'est à 0, aucun trafic ne passe
```

## 3. Vérifier que le forwarding IP est activé

```bash
# Vérifier
sysctl net.ipv4.ip_forward

# Doit retourner : net.ipv4.ip_forward = 1
# Si c'est 0, active-le :
sudo sysctl -w net.ipv4.ip_forward=1
```

## 4. Vérifier les routes

```bash
# Voir les routes
ip route show

# Tu devrais voir des routes vers 100.64.0.0/16 via wg-connector
```

## 5. Tester la connectivité depuis le connecteur

```bash
# Depuis le serveur du connecteur, tester vers le réseau interne
ping -c 3 192.168.75.130

# Si ça ne fonctionne pas, le problème est ailleurs
```

## 6. Vérifier que le client est bien connecté

Depuis ton PC Windows avec l'agent :
- Vérifie que WireGuard est actif
- Vérifie ton IP tunnel (devrait être dans 100.64.0.0/16)
- Vérifie les routes vers 192.168.75.0/24

## 7. Tester avec tcpdump (plus direct)

```bash
# Installer tcpdump si nécessaire
sudo apt install -y tcpdump

# Capturer le trafic sur l'interface WireGuard
sudo tcpdump -i wg-connector -n -v

# Filtrer uniquement le trafic vers 192.168.75.130
sudo tcpdump -i wg-connector -n -v "dst 192.168.75.130"
```

Si tcpdump montre du trafic mais pas les logs iptables, le problème vient des règles LOG.

## 8. Vérifier les logs système

```bash
# Voir tous les logs kernel récents
sudo dmesg | tail -50

# Voir les logs journalctl
sudo journalctl -k | tail -50
```

## 9. Forcer l'ajout des règles LOG manuellement

Si les règles ne sont pas présentes, ajoute-les manuellement :

```bash
# Remplacer d437f85c par les 8 premiers caractères de ton Connector ID
CONNECTOR_ID="d437f85c"

# Ajouter la règle LOG pour le trafic entrant
sudo iptables -A FORWARD \
  -s 100.64.0.0/16 -d 192.168.75.0/24 \
  -j LOG --log-prefix "ZTNA-CONNECTOR[$CONNECTOR_ID]: " --log-level 4

# Ajouter la règle LOG pour le trafic sortant
sudo iptables -A FORWARD \
  -s 192.168.75.0/24 -d 100.64.0.0/16 \
  -j LOG --log-prefix "ZTNA-CONNECTOR[$CONNECTOR_ID]: " --log-level 4

# Vérifier qu'elles sont bien ajoutées
sudo iptables -L FORWARD -n -v | grep LOG
```

## 10. Test complet

```bash
# Terminal 1 : Surveiller les logs
sudo journalctl -k -f | grep ZTNA-CONNECTOR

# Terminal 2 : Vérifier les règles
sudo iptables -L FORWARD -n -v | grep LOG

# Terminal 3 : Vérifier WireGuard
watch -n 1 sudo wg show wg-connector

# Depuis ton PC Windows : Tester
ping 192.168.75.130
```

Si après tout ça tu ne vois toujours rien, le trafic ne passe probablement pas par le connecteur.
