# 🔧 Fix : Routage PoP → Connecteur

Si `ping -c 3 192.168.75.130` depuis le PoP ne fonctionne pas, voici comment corriger.

## 1. Vérifier les routes sur le PoP

### Sur le VPS PoP

```bash
# Voir toutes les routes
ip route show

# Vérifier s'il y a une route vers 192.168.75.0/24
ip route show | grep 192.168.75
```

**Problème probable** : Il n'y a pas de route vers 192.168.75.0/24 via l'interface WireGuard du connecteur.

## 2. Vérifier WireGuard sur le PoP

```bash
# Voir la configuration WireGuard
sudo wg show wg0

# Voir les détails complets
sudo wg show wg0 dump
```

**Vérifie que** :
- Le connecteur est bien dans les pairs (peer)
- Le connecteur a `AllowedIPs` qui inclut `192.168.75.0/24` ou `100.65.0.0/16`
- La dernière poignée de main (latest handshake) est récente

## 3. Ajouter la route manuellement (temporaire)

### Sur le VPS PoP

```bash
# Trouver l'IP tunnel du connecteur (ex: 100.65.0.1)
sudo wg show wg0 | grep -A 5 "peer"

# Ajouter la route vers 192.168.75.0/24 via l'IP tunnel du connecteur
# Remplace 100.65.0.1 par l'IP réelle du connecteur
sudo ip route add 192.168.75.0/24 via 100.65.0.1 dev wg0

# Vérifier que la route est ajoutée
ip route show | grep 192.168.75
```

**Teste maintenant** :
```bash
ping -c 3 192.168.75.130
```

## 4. Vérifier le forwarding IP sur le PoP

```bash
# Vérifier
sysctl net.ipv4.ip_forward

# Si c'est 0, activer
sudo sysctl -w net.ipv4.ip_forward=1

# Rendre permanent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

## 5. Vérifier les règles iptables sur le PoP

```bash
# Voir les règles FORWARD
sudo iptables -L FORWARD -n -v

# Voir les règles NAT
sudo iptables -t nat -L -n -v
```

**Il devrait y avoir** :
- Une règle FORWARD pour permettre le trafic entre wg0 et les réseaux du connecteur
- Une règle NAT si nécessaire

## 6. Vérifier le connecteur

### Sur le serveur du connecteur

```bash
# Vérifier WireGuard
sudo wg show wg-connector

# Vérifier les routes
ip route show

# Vérifier le forwarding IP
sysctl net.ipv4.ip_forward
# Doit être à 1

# Vérifier les règles iptables
sudo iptables -L FORWARD -n -v
sudo iptables -t nat -L -n -v
```

## 7. Tester depuis le connecteur

### Sur le serveur du connecteur

```bash
# Tester vers 192.168.75.130 depuis le connecteur lui-même
ping -c 3 192.168.75.130

# Si ça ne fonctionne pas, l'IP n'existe pas ou ne répond pas
```

## 8. Configuration automatique (à implémenter)

Le PoP devrait automatiquement ajouter les routes vers les réseaux des connecteurs quand un connecteur s'enregistre. Vérifie dans le code du PoP si cette fonctionnalité existe.

## 9. Solution temporaire : Script de routage

Crée un script sur le PoP pour ajouter automatiquement les routes :

```bash
# /usr/local/bin/ztna-add-routes.sh
#!/bin/bash

# Récupérer les connecteurs depuis l'API du Control Plane
# Pour chaque connecteur, ajouter la route vers ses réseaux

# Exemple manuel :
sudo ip route add 192.168.75.0/24 via 100.65.0.1 dev wg0
```

## 10. Vérifier la configuration dans le Control Plane

Le Control Plane devrait configurer le PoP avec les bonnes routes quand un connecteur s'enregistre. Vérifie dans le dashboard :
- Le connecteur est bien assigné à un PoP
- Les réseaux du connecteur sont corrects (192.168.75.0/24)
