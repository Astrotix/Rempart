# 🔍 Monitorer le PoP dans Docker

Comment vérifier si le PoP reçoit les requêtes ping vers 192.168.75.130.

## 1. Voir les logs du PoP

```bash
# Voir les logs en temps réel
docker-compose logs -f pop

# Ou si le service s'appelle différemment
docker-compose logs -f pop-service

# Voir les dernières 100 lignes
docker-compose logs --tail 100 pop
```

## 2. Entrer dans le conteneur PoP

```bash
# Entrer dans le conteneur
docker-compose exec pop sh

# Ou si le service a un autre nom
docker-compose exec pop-service sh
```

Une fois dans le conteneur :

### Vérifier les statistiques WireGuard

```bash
# Voir les statistiques WireGuard
wg show

# Voir en temps réel (toutes les 2 secondes)
watch -n 2 wg show
```

### Vérifier les interfaces réseau

```bash
# Voir les interfaces réseau
ip addr show

# Voir les routes
ip route show

# Voir les statistiques de trafic
ip -s link show
```

### Monitorer le trafic avec tcpdump

```bash
# Installer tcpdump dans le conteneur (si pas déjà installé)
apk add tcpdump  # Pour Alpine Linux
# ou
apt install tcpdump  # Pour Debian/Ubuntu

# Capturer le trafic sur l'interface WireGuard
tcpdump -i wg0 -n -v

# Filtrer uniquement le trafic vers 192.168.75.130
tcpdump -i wg0 -n -v "dst 192.168.75.130"

# Filtrer les pings (ICMP)
tcpdump -i wg0 -n -v "icmp and dst 192.168.75.130"
```

## 3. Monitorer depuis l'hôte Docker

### Voir les statistiques du conteneur

```bash
# Voir les statistiques réseau du conteneur
docker stats pop

# Voir les détails du conteneur
docker inspect pop
```

### Capturer le trafic depuis l'hôte

```bash
# Trouver l'interface réseau du conteneur
docker inspect pop | grep -A 20 "NetworkSettings"

# Ou utiliser l'interface veth
ip link show | grep veth

# Capturer le trafic sur l'interface veth
sudo tcpdump -i vethXXXXX -n -v "dst 192.168.75.130"
```

## 4. Vérifier les logs système du PoP

Si le PoP log des événements, vérifie les logs :

```bash
# Logs du conteneur
docker-compose logs pop | grep -i "192.168.75.130"

# Logs en temps réel
docker-compose logs -f pop | grep -i "ping\|icmp\|192.168.75.130"
```

## 5. Test complet depuis l'extérieur

### Depuis ton PC Windows

```powershell
# Tester le ping
ping 192.168.75.130

# Tester avec plusieurs paquets
ping -n 10 192.168.75.130
```

### Pendant le ping, surveiller le PoP

Dans un terminal, surveille les logs :

```bash
# Terminal 1 : Logs du PoP
docker-compose logs -f pop

# Terminal 2 : Statistiques WireGuard (dans le conteneur)
docker-compose exec pop wg show

# Terminal 3 : Trafic réseau (dans le conteneur)
docker-compose exec pop tcpdump -i wg0 -n -v "icmp"
```

## 6. Vérifier la configuration WireGuard du PoP

```bash
# Entrer dans le conteneur
docker-compose exec pop sh

# Voir la configuration WireGuard
wg show

# Voir les pairs connectés
wg show wg0 peers

# Voir les statistiques détaillées
wg show wg0 dump
```

Tu devrais voir :
- Les pairs (clients et connecteurs) connectés
- Les bytes transférés (transfer) qui augmentent
- Les dernières poignées de main (latest handshake)

## 7. Vérifier les routes et le forwarding

```bash
# Entrer dans le conteneur
docker-compose exec pop sh

# Vérifier le forwarding IP
sysctl net.ipv4.ip_forward
# Doit retourner : net.ipv4.ip_forward = 1

# Voir les routes
ip route show

# Vérifier les règles iptables
iptables -L -n -v
iptables -t nat -L -n -v
```

## 8. Diagnostic étape par étape

### Étape 1 : Vérifier que le PoP est en ligne

```bash
# Voir le statut du conteneur
docker-compose ps pop

# Voir les logs récents
docker-compose logs --tail 50 pop
```

### Étape 2 : Vérifier WireGuard

```bash
# Entrer dans le conteneur
docker-compose exec pop sh

# Voir les statistiques
wg show
```

Si tu vois des pairs connectés et des bytes transférés, le PoP reçoit du trafic.

### Étape 3 : Tester depuis le PoP lui-même

```bash
# Entrer dans le conteneur
docker-compose exec pop sh

# Tester la connectivité vers le connecteur
ping -c 3 192.168.75.130

# Si ça ne fonctionne pas, le problème est dans le routage
```

### Étape 4 : Monitorer en temps réel

```bash
# Terminal 1 : Logs
docker-compose logs -f pop

# Terminal 2 : WireGuard stats
watch -n 1 'docker-compose exec pop wg show'

# Terminal 3 : Depuis ton PC, ping
ping 192.168.75.130
```

## 9. Commandes rapides

```bash
# Voir les logs en temps réel
docker-compose logs -f pop

# Voir WireGuard stats
docker-compose exec pop wg show

# Monitorer le trafic
docker-compose exec pop tcpdump -i wg0 -n -v "icmp"

# Voir les stats réseau du conteneur
docker stats pop
```

## 10. Troubleshooting

### Le PoP ne reçoit pas de trafic

1. Vérifie que le conteneur est bien démarré :
   ```bash
   docker-compose ps pop
   ```

2. Vérifie que WireGuard est configuré :
   ```bash
   docker-compose exec pop wg show
   ```

3. Vérifie que les pairs sont connectés :
   ```bash
   docker-compose exec pop wg show | grep -A 5 "peer"
   ```

4. Vérifie les logs pour des erreurs :
   ```bash
   docker-compose logs pop | grep -i error
   ```

### Le trafic passe mais ne va pas vers 192.168.75.130

1. Vérifie les routes :
   ```bash
   docker-compose exec pop ip route show
   ```

2. Vérifie le forwarding :
   ```bash
   docker-compose exec pop sysctl net.ipv4.ip_forward
   ```

3. Vérifie les règles iptables :
   ```bash
   docker-compose exec pop iptables -L -n -v
   ```
