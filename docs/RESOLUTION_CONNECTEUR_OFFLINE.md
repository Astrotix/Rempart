# 🔧 Résolution : Connecteur marqué ONLINE mais dernier contact il y a 2h

## Problème identifié

Le connecteur "OVH Toulouse" est marqué comme "ONLINE" dans le dashboard, mais le dernier contact date de **2 heures**. Cela signifie que :

1. ❌ Le connecteur n'envoie plus de heartbeats au Control Plane
2. ⚠️ Le statut n'est pas mis à jour automatiquement (bug à corriger)
3. 🔴 Le connecteur est probablement hors ligne ou ne peut plus communiquer

---

## ✅ Solution immédiate : Vérifier et redémarrer le connecteur

### Étape 1 : Vérifier que le connecteur tourne toujours

**Sur le serveur où tourne le connecteur**, exécute :

```bash
# Vérifier si le processus tourne
ps aux | grep ztna-connector

# Ou si c'est un service systemd
sudo systemctl status ztna-connector

# Vérifier les logs
sudo journalctl -u ztna-connector -f --since "2 hours ago"
```

**Si le connecteur ne tourne pas :**
- Redémarre-le (voir Étape 2)

**Si le connecteur tourne mais n'envoie pas de heartbeats :**
- Vérifie les logs pour voir les erreurs
- Vérifie la connectivité vers le Control Plane

---

### Étape 2 : Redémarrer le connecteur

**Si c'est un service systemd :**
```bash
sudo systemctl restart ztna-connector
sudo systemctl status ztna-connector
```

**Si tu l'as lancé manuellement :**
1. Trouve le processus : `ps aux | grep ztna-connector`
2. Tue-le : `kill <PID>`
3. Relance-le avec la commande d'installation du dashboard

---

### Étape 3 : Vérifier la connectivité vers le Control Plane

**Sur le serveur du connecteur :**
```bash
# Tester la connectivité HTTP vers le Control Plane
curl -v http://176.136.202.205:8080/api/health

# Tester l'envoi d'un heartbeat manuel (remplace les valeurs)
curl -X POST http://176.136.202.205:8080/api/connector/heartbeat \
  -H "Content-Type: application/json" \
  -d '{
    "connector_id": "TON_CONNECTOR_ID",
    "token": "TON_TOKEN"
  }'
```

**Si curl échoue :**
- Vérifie le firewall (le connecteur doit pouvoir accéder au Control Plane sur le port 8080)
- Vérifie que le Control Plane est accessible depuis l'extérieur

---

### Étape 4 : Vérifier la configuration du connecteur

**Vérifie que le connecteur a la bonne configuration :**
```bash
# Vérifier la config WireGuard
sudo wg show

# Vérifier que l'interface WireGuard est active
ip link show wg0

# Vérifier les routes
ip route | grep 100.64
```

---

## 🔄 Solution à long terme : Mise à jour automatique du statut

Le système devrait automatiquement marquer les connecteurs comme "OFFLINE" s'ils n'ont pas envoyé de heartbeat depuis plus de 5 minutes.

**Pour l'instant, tu peux :**
1. Redémarrer le connecteur (voir Étape 2)
2. Attendre quelques secondes
3. Rafraîchir le dashboard
4. Vérifier que le "Dernier contact" est mis à jour

---

## 📋 Checklist de vérification

- [ ] Le connecteur tourne toujours (processus actif)
- [ ] Les logs du connecteur ne montrent pas d'erreurs
- [ ] Le connecteur peut accéder au Control Plane (curl fonctionne)
- [ ] WireGuard est actif sur le connecteur (`wg show` fonctionne)
- [ ] Le forwarding IP est activé (`sysctl net.ipv4.ip_forward`)
- [ ] Les règles iptables NAT sont présentes
- [ ] Après redémarrage, le "Dernier contact" se met à jour dans le dashboard

---

## 🚨 Si le connecteur ne peut pas être redémarré

Si tu ne peux pas accéder au serveur du connecteur :

1. **Supprime le connecteur** dans le dashboard
2. **Crée un nouveau connecteur** avec un nouveau token
3. **Réinstalle le connecteur** sur le serveur avec le nouveau token

Cela créera une nouvelle configuration WireGuard et réinitialisera le statut.

---

## 🔍 Diagnostic avancé

**Vérifier les logs du Control Plane :**
```bash
# Dans Docker
docker-compose logs api | grep connector

# Chercher les erreurs de heartbeat
docker-compose logs api | grep -i "heartbeat\|connector"
```

**Vérifier les métriques du connecteur :**
- Le connecteur devrait envoyer un heartbeat toutes les 30 secondes
- Si aucun heartbeat n'est reçu depuis 2h, le connecteur est probablement arrêté

---

## 💡 Prévention

Pour éviter ce problème à l'avenir :

1. **Configure un service systemd** pour le connecteur (redémarrage automatique)
2. **Configure un monitoring** pour alerter si le connecteur est hors ligne
3. **Ajoute un healthcheck** dans le code du connecteur

---

Une fois le connecteur redémarré et les heartbeats repartis, le problème de connectivité devrait être résolu (à condition que le PoP ait aussi les bonnes règles iptables).
