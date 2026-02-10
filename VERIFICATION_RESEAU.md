# 🔍 Guide de Vérification d'Accès au Réseau ZTNA

## 1. Vérifier que WireGuard est actif

### Windows (PowerShell en Administrateur)
```powershell
# Vérifier que l'interface WireGuard existe
Get-NetAdapter | Where-Object {$_.Name -like "*wg*" -or $_.Name -like "*WireGuard*"}

# Voir les interfaces réseau
ipconfig /all

# Vérifier les routes WireGuard
route print | findstr "100.64"
```

### Via WireGuard GUI
- Ouvre l'application WireGuard
- Vérifie que le tunnel `wg-ztna` est actif (bouton "Activer" ou statut "Connecté")

## 2. Vérifier ton IP Tunnel

### Dans l'interface graphique de l'agent
- Une fois connecté, l'interface affiche ton **IP Tunnel** (ex: `100.64.0.1`)
- Cette IP devrait être dans la plage `100.64.0.0/16`

### Via PowerShell
```powershell
# Voir toutes les IPs de tes interfaces
ipconfig

# Filtrer pour voir l'IP WireGuard
ipconfig | Select-String "100.64"
```

## 3. Vérifier les routes réseau

```powershell
# Voir toutes les routes
route print

# Filtrer les routes WireGuard (réseaux 100.64.x.x et 100.65.x.x)
route print | findstr "100.64 100.65"
```

Tu devrais voir des routes vers :
- `100.64.0.0/16` (réseau des utilisateurs)
- `100.65.0.0/16` (réseau des connecteurs)
- Les réseaux exposés par ton connecteur (ex: `192.168.75.0/24`)

## 4. Tester la connectivité vers les réseaux du connecteur

### Étape 1 : Vérifier quel connecteur tu utilises
- Va dans le dashboard admin → "Politiques"
- Trouve la politique qui t'autorise
- Note le **connecteur** et les **réseaux** autorisés (ex: `192.168.75.0/24`)

### Étape 2 : Tester avec ping
```powershell
# Tester la connectivité vers un réseau autorisé
# Remplace 192.168.75.1 par une IP réelle de ton réseau
ping 192.168.75.1

# Tester vers plusieurs IPs
ping 192.168.75.10
ping 192.168.75.100
```

### Étape 3 : Tester avec telnet (si un service écoute)
```powershell
# Tester un port spécifique (ex: SSH sur port 22)
Test-NetConnection -ComputerName 192.168.75.10 -Port 22

# Tester HTTP (port 80)
Test-NetConnection -ComputerName 192.168.75.10 -Port 80
```

## 5. Vérifier via le dashboard admin

1. Va sur `http://176.136.202.205:3000`
2. Section **"Tableau de bord"** → Vérifie :
   - **Agents connectés** : Tu devrais apparaître
   - **Sessions actives** : Devrait être > 0
3. Section **"Politiques"** → Vérifie que tu as une politique **ALLOW** active pour :
   - **Source** : Ton utilisateur
   - **Destination** : Le connecteur
   - **Réseaux** : Les réseaux que tu veux accéder
   - **Ports** : `*` (tous) ou les ports spécifiques

## 6. Vérifier les logs de l'agent

Dans la console où tu as lancé l'agent, tu devrais voir :
```
[ZTNA] Tunnel WireGuard établi !
[ZTNA] CONNECTE — Ctrl+C pour déconnecter
```

## 7. Test complet : Accéder à une ressource

### Si tu as un serveur SSH dans le réseau distant :
```powershell
ssh user@192.168.75.10
```

### Si tu as un serveur web :
```powershell
# Dans PowerShell
Invoke-WebRequest -Uri "http://192.168.75.10" -UseBasicParsing

# Ou dans le navigateur
# http://192.168.75.10
```

## ⚠️ Problèmes courants

### "Ping ne fonctionne pas"
- Vérifie que tu as une **politique ALLOW** dans le dashboard
- Vérifie que le réseau est bien dans les **réseaux autorisés** de la politique
- Vérifie que le connecteur est **en ligne** (statut "online" dans le dashboard)

### "WireGuard ne démarre pas"
- Lance l'agent **en Administrateur** (clic droit → Exécuter en tant qu'administrateur)
- Vérifie que WireGuard pour Windows est installé : https://www.wireguard.com/install/

### "Je vois mon IP tunnel mais je ne peux pas accéder aux réseaux"
- **Cause probable** : Pas de politique ou politique mal configurée
- **Solution** : Crée/modifie une politique dans le dashboard avec :
  - Source = ton utilisateur
  - Destination = le connecteur
  - Réseaux = les réseaux à accéder (ex: `192.168.75.0/24`)
  - Ports = `*` (tous) ou les ports spécifiques
  - Action = **ALLOW**

## 📊 Exemple de test complet

```powershell
# 1. Vérifier l'interface WireGuard
Get-NetAdapter | Where-Object {$_.Name -like "*wg*"}

# 2. Vérifier ton IP tunnel
ipconfig | Select-String "100.64"

# 3. Vérifier les routes
route print | findstr "192.168.75"

# 4. Tester la connectivité
ping 192.168.75.1

# 5. Tester un service (ex: SSH)
Test-NetConnection -ComputerName 192.168.75.10 -Port 22
```

## ✅ Checklist de vérification

- [ ] WireGuard est actif (interface visible)
- [ ] IP tunnel assignée (100.64.x.x visible dans ipconfig)
- [ ] Routes vers les réseaux distants présentes
- [ ] Politique ALLOW créée dans le dashboard
- [ ] Connecteur en ligne (statut "online")
- [ ] Ping vers une IP du réseau distant fonctionne
- [ ] Accès aux services (SSH, HTTP, etc.) fonctionne
