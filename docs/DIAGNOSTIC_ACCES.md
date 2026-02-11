# 🔍 Guide de Diagnostic d'Accès au Réseau ZTNA

## Problème : Je ne peux pas accéder à `192.168.75.130` malgré la politique

### Étape 1 : Vérifier la configuration WireGuard

#### Windows (PowerShell en Admin)
```powershell
# 1. Vérifier que le tunnel est actif
Get-NetAdapter | Where-Object {$_.Name -like "*wg*"}

# 2. Voir la configuration WireGuard
Get-Content "C:\ProgramData\WireGuard\wg-ztna.conf"

# 3. Vérifier les AllowedIPs dans la config
# Tu devrais voir : AllowedIPs = 100.65.0.0/16, 192.168.75.0/24
```

**Si `192.168.75.0/24` n'est PAS dans AllowedIPs :**
- Le problème vient de la récupération des politiques
- Vérifie les logs de l'API (voir Étape 2)

#### Via WireGuard GUI
1. Ouvre WireGuard
2. Clique sur le tunnel `wg-ztna`
3. Vérifie la ligne `AllowedIPs` dans la section `[Peer]`
4. Elle devrait contenir : `100.65.0.0/16, 192.168.75.0/24`

### Étape 2 : Vérifier les routes système

```powershell
# Voir toutes les routes
route print

# Filtrer pour voir les routes vers 192.168.75.0/24
route print | findstr "192.168.75"

# Vérifier que la route existe et pointe vers l'interface WireGuard
# Tu devrais voir quelque chose comme :
# 192.168.75.0    255.255.255.0  100.64.x.x  wg-ztna
```

**Si la route n'existe pas :**
- WireGuard devrait créer la route automatiquement
- Vérifie que le tunnel est bien actif

### Étape 3 : Vérifier la connectivité vers le PoP

```powershell
# Tester la connectivité vers ton IP tunnel (100.64.x.x)
ping 100.64.0.6

# Tester la connectivité vers le réseau des connecteurs (100.65.x.x)
# Remplace 100.65.0.1 par l'IP tunnel du connecteur (visible dans le dashboard)
ping 100.65.0.1
```

**Si le ping vers 100.65.x.x ne fonctionne pas :**
- Le connecteur n'est peut-être pas en ligne
- Vérifie dans le dashboard que le connecteur est "online"

### Étape 4 : Vérifier le connecteur dans le dashboard

1. Va sur `http://176.136.202.205:3000`
2. Section **"Connecteurs"** :
   - Vérifie que le connecteur est **"En ligne"** (statut vert)
   - Vérifie que les **réseaux** du connecteur incluent `192.168.75.0/24`
   - Note l'**IP Tunnel** du connecteur (ex: `100.65.0.1`)

### Étape 5 : Vérifier la politique dans le dashboard

1. Section **"Politiques"** :
   - Vérifie qu'il existe une politique **ALLOW** pour :
     - **Source** : Ton utilisateur (Guillaume)
     - **Destination** : Le connecteur qui expose `192.168.75.0/24`
     - **Réseaux** : `192.168.75.0/24` (doit être exactement ça)
     - **Ports** : `*` (tous) ou les ports spécifiques
     - **Action** : **ALLOW**
     - **Statut** : **Activée** (checkbox cochée)

### Étape 6 : Tester la connectivité étape par étape

```powershell
# 1. Tester ton IP tunnel (doit fonctionner)
ping 100.64.0.6

# 2. Tester l'IP tunnel du connecteur (doit fonctionner si connecteur en ligne)
ping 100.65.0.1  # Remplace par l'IP réelle du connecteur

# 3. Tester une IP du réseau distant
ping 192.168.75.130

# 4. Traceroute pour voir où ça bloque
tracert 192.168.75.130
```

### Étape 7 : Vérifier les logs de l'API

Dans les logs Docker de l'API, lors de la connexion de l'agent, tu devrais voir :
```
Politiques trouvees pour user ...: 1
Politique: ..., DestNetworks: [192.168.75.0/24]
Reseau autorise ajoute: 192.168.75.0/24
Reseaux finaux pour split-tunneling: [100.65.0.0/16 192.168.75.0/24]
```

**Si tu ne vois pas ces logs :**
- Les politiques ne sont peut-être pas chargées
- Vérifie que la politique est bien créée et activée

### Étape 8 : Vérifier le PoP

Le PoP doit avoir des routes vers le connecteur pour les réseaux `192.168.75.0/24`.

**Sur le serveur PoP (Ubuntu) :**
```bash
# Vérifier que WireGuard est actif
sudo wg show

# Vérifier les routes
ip route | grep 192.168.75

# Vérifier le forwarding IP
sysctl net.ipv4.ip_forward
# Doit retourner : net.ipv4.ip_forward = 1
```

**Si le forwarding n'est pas activé :**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

### Étape 9 : Vérifier le connecteur

**Sur le serveur où tourne le connecteur :**
```bash
# Vérifier que WireGuard est actif
sudo wg show

# Vérifier le forwarding IP
sysctl net.ipv4.ip_forward
# Doit retourner : net.ipv4.ip_forward = 1

# Vérifier les routes iptables NAT
sudo iptables -t nat -L -n | grep 192.168.75
```

**Si le forwarding n'est pas activé :**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

**Si les règles iptables NAT manquent :**
Le connecteur devrait les créer automatiquement, mais tu peux les ajouter manuellement :
```bash
sudo iptables -t nat -A POSTROUTING -s 100.64.0.0/16 -d 192.168.75.0/24 -j MASQUERADE
```

### Étape 10 : Test complet avec traceroute

```powershell
# Traceroute vers l'IP cible
tracert 192.168.75.130
```

**Résultat attendu :**
1. `100.64.x.x` (ton IP tunnel)
2. `100.65.x.x` (IP tunnel du connecteur)
3. `192.168.75.130` (destination finale)

**Si ça bloque à l'étape 2 :**
- Le PoP ne route pas vers le connecteur
- Vérifie que le PoP a bien le peer du connecteur configuré

**Si ça bloque à l'étape 3 :**
- Le connecteur ne route pas vers le réseau interne
- Vérifie le forwarding IP et les règles iptables sur le connecteur

## 🔧 Commandes de diagnostic rapide

### Sur Windows (Client)
```powershell
# Vérifier la config WireGuard
Get-Content "C:\ProgramData\WireGuard\wg-ztna.conf" | Select-String "AllowedIPs"

# Vérifier les routes
route print | findstr "192.168.75"

# Tester la connectivité
ping 192.168.75.130
Test-NetConnection -ComputerName 192.168.75.130 -Port 22
```

### Sur le PoP (Ubuntu)
```bash
# Vérifier WireGuard
sudo wg show

# Vérifier les routes
ip route | grep 192.168.75

# Vérifier le forwarding
sysctl net.ipv4.ip_forward
```

### Sur le Connecteur (Ubuntu)
```bash
# Vérifier WireGuard
sudo wg show

# Vérifier le forwarding
sysctl net.ipv4.ip_forward

# Vérifier les règles NAT
sudo iptables -t nat -L -n -v
```

## ⚠️ Problèmes courants et solutions

### Problème 1 : `AllowedIPs` ne contient pas `192.168.75.0/24`
**Cause :** Les politiques ne sont pas récupérées correctement
**Solution :**
1. Vérifie les logs de l'API lors de la connexion
2. Vérifie que la politique est bien créée et activée
3. Reconnecte-toi avec l'agent

### Problème 2 : Ping vers `192.168.75.130` timeout
**Causes possibles :**
1. Le connecteur n'est pas en ligne
2. Le PoP ne route pas vers le connecteur
3. Le connecteur n'a pas le forwarding IP activé
4. Les règles iptables NAT manquent sur le connecteur

**Solution :**
1. Vérifie le statut du connecteur dans le dashboard
2. Vérifie le forwarding IP sur le PoP et le connecteur
3. Vérifie les règles iptables sur le connecteur

### Problème 3 : Traceroute bloque à l'étape 2
**Cause :** Le PoP ne route pas vers le connecteur
**Solution :**
- Le PoP doit avoir le peer du connecteur configuré dans WireGuard
- Vérifie avec `sudo wg show` sur le PoP

### Problème 4 : Traceroute bloque à l'étape 3
**Cause :** Le connecteur ne route pas vers le réseau interne
**Solution :**
- Active le forwarding IP : `sudo sysctl -w net.ipv4.ip_forward=1`
- Ajoute les règles iptables NAT (le connecteur devrait le faire automatiquement)

## 📊 Checklist complète

- [ ] WireGuard tunnel actif sur le client
- [ ] `AllowedIPs` contient `192.168.75.0/24` dans la config WireGuard
- [ ] Route système vers `192.168.75.0/24` existe
- [ ] Connecteur en ligne dans le dashboard
- [ ] Politique ALLOW créée et activée pour `192.168.75.0/24`
- [ ] PoP en ligne et accessible
- [ ] Forwarding IP activé sur le PoP
- [ ] Forwarding IP activé sur le connecteur
- [ ] Règles iptables NAT configurées sur le connecteur
- [ ] Ping vers `100.65.x.x` (IP tunnel connecteur) fonctionne
- [ ] Ping vers `192.168.75.130` fonctionne
