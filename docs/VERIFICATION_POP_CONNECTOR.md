# 🔍 Vérification PoP et Connecteur

## Problème : Ping timeout vers 192.168.75.130

Le diagnostic montre que :
- ✅ Configuration WireGuard correcte (AllowedIPs contient 192.168.75.0/24)
- ✅ Routes système correctes
- ❌ Ping et traceroute timeout

Cela signifie que le problème est au niveau du **PoP** ou du **Connecteur**.

---

## 📋 Checklist de Vérification

### 1. Vérifier le Connecteur dans le Dashboard

1. Va sur `http://176.136.202.205:3000`
2. Section **"Connecteurs"** :
   - ✅ Le connecteur doit être **"En ligne"** (statut vert)
   - ✅ Les **réseaux** doivent inclure `192.168.75.0/24`
   - ✅ Note l'**IP Tunnel** du connecteur (ex: `100.65.0.1`)

**Si le connecteur est hors ligne :**
- Vérifie que le service tourne sur le serveur du connecteur
- Vérifie les logs du connecteur

---

### 2. Vérifier le PoP (sur le serveur PoP)

**Connecte-toi en SSH sur ton serveur PoP** et exécute :

```bash
# 1. Vérifier que WireGuard est actif
sudo wg show

# Tu devrais voir :
# - L'interface wg0 avec des peers (utilisateurs et connecteurs)
# - Les AllowedIPs pour chaque peer

# 2. Vérifier le forwarding IP
sysctl net.ipv4.ip_forward
# Doit retourner : net.ipv4.ip_forward = 1

# Si ce n'est pas le cas :
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# 3. Vérifier les routes vers les connecteurs
ip route | grep 100.65
# Tu devrais voir des routes vers les IPs tunnel des connecteurs

# 4. Vérifier les règles iptables pour router vers les réseaux des connecteurs
sudo iptables -t nat -L -n -v | grep 192.168.75
# Si aucune règle n'existe, il faut les ajouter (voir ci-dessous)
```

---

### 3. Ajouter les règles iptables sur le PoP

Le PoP doit router le trafic depuis les utilisateurs (100.64.0.0/16) vers les connecteurs (100.65.0.0/16) et leurs réseaux.

**Sur le serveur PoP, exécute :**

```bash
# 1. Activer le forwarding IP (si pas déjà fait)
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# 2. Ajouter les règles iptables pour router vers les connecteurs
# Règle 1 : NAT pour le trafic des utilisateurs vers les connecteurs
sudo iptables -t nat -A POSTROUTING -s 100.64.0.0/16 -d 100.65.0.0/16 -j ACCEPT

# Règle 2 : NAT pour le trafic des utilisateurs vers les réseaux des connecteurs
# Remplace 192.168.75.0/24 par les réseaux de TON connecteur
sudo iptables -t nat -A POSTROUTING -s 100.64.0.0/16 -d 192.168.75.0/24 -j MASQUERADE

# Règle 3 : Forwarding du trafic vers les connecteurs
sudo iptables -A FORWARD -s 100.64.0.0/16 -d 100.65.0.0/16 -j ACCEPT
sudo iptables -A FORWARD -s 100.64.0.0/16 -d 192.168.75.0/24 -j ACCEPT

# 3. Vérifier les règles
sudo iptables -t nat -L -n -v
sudo iptables -L FORWARD -n -v
```

**Pour rendre ces règles permanentes :**

```bash
# Sur Ubuntu/Debian
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save

# Ou manuellement
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

### 4. Vérifier le Connecteur (sur le serveur du connecteur)

**Connecte-toi en SSH sur le serveur où tourne le connecteur** et exécute :

```bash
# 1. Vérifier que WireGuard est actif
sudo wg show

# Tu devrais voir :
# - L'interface WireGuard avec le peer du PoP
# - L'IP tunnel du connecteur (ex: 100.65.0.1)

# 2. Vérifier le forwarding IP
sysctl net.ipv4.ip_forward
# Doit retourner : net.ipv4.ip_forward = 1

# Si ce n'est pas le cas :
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# 3. Vérifier les règles iptables NAT
sudo iptables -t nat -L -n -v | grep 192.168.75

# Tu devrais voir une règle comme :
# MASQUERADE  all  --  100.64.0.0/16  192.168.75.0/24

# Si la règle n'existe pas, le connecteur devrait l'ajouter automatiquement
# Sinon, ajoute-la manuellement :
sudo iptables -t nat -A POSTROUTING -s 100.64.0.0/16 -d 192.168.75.0/24 -j MASQUERADE

# 4. Vérifier que le connecteur peut accéder au réseau local
ping -c 2 192.168.75.130
# Doit fonctionner depuis le serveur du connecteur
```

---

### 5. Test de Connectivité Étape par Étape

**Depuis ton PC Windows (avec l'agent connecté) :**

```powershell
# 1. Tester ton IP tunnel (doit fonctionner)
ping 100.64.0.6

# 2. Tester l'IP tunnel du PoP (via WireGuard)
# Remplace par l'IP publique du PoP
ping <IP_PUBLIQUE_POP>

# 3. Tester l'IP tunnel du connecteur (doit fonctionner si connecteur en ligne)
ping 100.65.0.1  # Remplace par l'IP tunnel réelle du connecteur

# 4. Tester l'IP du réseau distant
ping 192.168.75.130
```

**Si le ping vers 100.65.0.1 fonctionne mais pas vers 192.168.75.130 :**
- Le problème est au niveau du connecteur (forwarding IP ou règles iptables)

**Si le ping vers 100.65.0.1 ne fonctionne pas :**
- Le problème est au niveau du PoP (règles iptables manquantes)

---

### 6. Vérifier les Logs

**Sur le PoP :**
```bash
# Logs du service PoP
sudo journalctl -u ztna-pop -f

# Ou si le service tourne en foreground
# Vérifie les logs dans le terminal où tu as lancé ztna-pop
```

**Sur le Connecteur :**
```bash
# Logs du service connecteur
sudo journalctl -u ztna-connector -f

# Ou si le service tourne en foreground
# Vérifie les logs dans le terminal où tu as lancé ztna-connector
```

---

## 🔧 Solution Rapide : Script de Configuration PoP

Crée un script sur le PoP pour configurer automatiquement les règles :

```bash
#!/bin/bash
# /opt/ztna/configure-pop-routing.sh

# Activer forwarding IP
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# Règles iptables pour router vers les connecteurs
iptables -t nat -A POSTROUTING -s 100.64.0.0/16 -d 100.65.0.0/16 -j ACCEPT
iptables -t nat -A POSTROUTING -s 100.64.0.0/16 -d 192.168.75.0/24 -j MASQUERADE
iptables -A FORWARD -s 100.64.0.0/16 -d 100.65.0.0/16 -j ACCEPT
iptables -A FORWARD -s 100.64.0.0/16 -d 192.168.75.0/24 -j ACCEPT

# Sauvegarder les règles
iptables-save > /etc/iptables/rules.v4

echo "Configuration PoP terminée"
```

**Exécute le script :**
```bash
sudo chmod +x /opt/ztna/configure-pop-routing.sh
sudo /opt/ztna/configure-pop-routing.sh
```

---

## 📊 Résumé du Flux de Trafic

```
Client (100.64.0.6)
    ↓ WireGuard
PoP (IP publique)
    ↓ WireGuard (100.65.0.0/16)
Connecteur (100.65.0.1)
    ↓ Routage local
Réseau interne (192.168.75.130)
```

**Points de vérification :**
1. ✅ Client → PoP : WireGuard tunnel actif
2. ✅ PoP → Connecteur : WireGuard peer configuré + règles iptables
3. ✅ Connecteur → Réseau interne : Forwarding IP + règles iptables NAT

---

## ⚠️ Problèmes Courants

### Problème 1 : PoP n'a pas de règles iptables
**Symptôme :** Ping vers 100.65.0.1 timeout
**Solution :** Ajouter les règles iptables sur le PoP (voir section 3)

### Problème 2 : Connecteur n'a pas le forwarding IP
**Symptôme :** Ping vers 100.65.0.1 OK mais ping vers 192.168.75.130 timeout
**Solution :** Activer le forwarding IP sur le connecteur

### Problème 3 : Connecteur n'a pas de règles iptables NAT
**Symptôme :** Ping vers 100.65.0.1 OK mais ping vers 192.168.75.130 timeout
**Solution :** Ajouter les règles iptables NAT sur le connecteur

### Problème 4 : Firewall bloque le trafic
**Symptôme :** Tout timeout
**Solution :** Vérifier ufw/iptables et autoriser le trafic WireGuard
