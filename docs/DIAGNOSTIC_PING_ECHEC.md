# 🔍 Diagnostic : Ping vers 192.168.75.130 échoue

Si le ping échoue et que tcpdump ne voit rien, voici comment diagnostiquer.

## 1. Vérifier que le client est bien connecté

### Depuis ton PC Windows

```powershell
# Vérifier que WireGuard est actif
Get-NetAdapter | Where-Object {$_.Name -like "*wg*"}

# Voir ton IP tunnel
ipconfig | Select-String "100.64"

# Vérifier les routes
route print | findstr "192.168.75"
```

Tu devrais voir :
- Une interface WireGuard active
- Une IP dans la plage 100.64.0.0/16
- Une route vers 192.168.75.0/24 via l'interface WireGuard

## 2. Vérifier que le PoP reçoit du trafic

### Sur le VPS PoP

```bash
# Voir les statistiques WireGuard
sudo wg show

# Tu devrais voir :
# - Les pairs connectés (clients et connecteurs)
# - Les bytes transférés (transfer) qui augmentent
# - Les dernières poignées de main (latest handshake)
```

Si les bytes ne augmentent pas quand tu ping, le trafic ne passe pas par WireGuard.

## 3. Vérifier que le connecteur est en ligne

### Dans le dashboard

- Va dans "Connecteurs"
- Vérifie que le statut est "ONLINE" (vert)
- Vérifie le "Dernier contact" (doit être récent)

### Sur le serveur du connecteur

```bash
# Vérifier que le connecteur tourne
ps aux | grep ztna-connector

# Vérifier WireGuard sur le connecteur
sudo wg show wg-connector

# Vérifier les routes
ip route show | grep 192.168.75
```

## 4. Vérifier le routage sur le PoP

### Sur le VPS PoP

```bash
# Vérifier le forwarding IP
sysctl net.ipv4.ip_forward
# Doit retourner : net.ipv4.ip_forward = 1

# Voir les routes
ip route show

# Vérifier les règles iptables
sudo iptables -L FORWARD -n -v
sudo iptables -t nat -L -n -v
```

## 5. Tester depuis le PoP vers le connecteur

### Sur le VPS PoP

```bash
# Tester la connectivité vers le connecteur
ping -c 3 192.168.75.130

# Si ça ne fonctionne pas, le problème est dans le routage PoP -> Connecteur
```

## 6. Vérifier la configuration WireGuard

### Sur le VPS PoP

```bash
# Voir la configuration complète
sudo wg show wg0 dump

# Vérifier que les pairs ont les bonnes AllowedIPs
# Le client doit avoir 192.168.75.0/24 dans ses AllowedIPs
# Le connecteur doit avoir 100.64.0.0/16 dans ses AllowedIPs
```

## 7. Vérifier les politiques dans le dashboard

- Va dans "Politiques"
- Vérifie qu'il y a une politique "allow" pour ton utilisateur
- Vérifie que la politique autorise l'accès à 192.168.75.0/24
- Vérifie que la politique est assignée au bon connecteur

## 8. Test de bout en bout

### Étape 1 : Vérifier le client

```powershell
# Depuis ton PC Windows
ping 192.168.75.130
```

### Étape 2 : Surveiller le PoP

```bash
# Sur le VPS PoP
sudo tcpdump -i wg0 -n -v "icmp"
```

### Étape 3 : Surveiller le connecteur

```bash
# Sur le serveur du connecteur
sudo tcpdump -i wg-connector -n -v "icmp and dst 192.168.75.130"
```

Si tu vois des paquets dans tcpdump mais que le ping échoue, le problème est dans le routage final vers 192.168.75.130.

## 9. Vérifier que 192.168.75.130 existe et répond

### Sur le serveur du connecteur

```bash
# Tester depuis le connecteur lui-même
ping -c 3 192.168.75.130

# Si ça ne fonctionne pas, l'IP n'existe pas ou ne répond pas
```

## 10. Checklist complète

- [ ] Client WireGuard actif et connecté
- [ ] Client a une IP dans 100.64.0.0/16
- [ ] Client a une route vers 192.168.75.0/24
- [ ] PoP reçoit du trafic (bytes transférés augmentent)
- [ ] Connecteur est ONLINE dans le dashboard
- [ ] Connecteur a WireGuard actif
- [ ] Politique autorise l'accès à 192.168.75.0/24
- [ ] Forwarding IP activé sur PoP et Connecteur
- [ ] 192.168.75.130 existe et répond depuis le connecteur
