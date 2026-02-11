# 🔄 Mise à jour du PoP sur le VPS

Commandes exactes pour mettre à jour le PoP avec le routage automatique.

## Sur le VPS PoP

### Option 1 : Si tu as cloné depuis Git

```bash
# Aller dans le répertoire du projet
cd ztna-sovereign

# Récupérer les dernières modifications
git pull

# Compiler le PoP
go build -o ztna-pop ./cmd/pop

# Arrêter l'ancien PoP (si lancé manuellement)
# Ctrl+C si en mode interactif, ou :
pkill ztna-pop

# Ou si c'est un service systemd :
sudo systemctl stop ztna-pop

# Relancer le PoP
# Si service systemd :
sudo systemctl start ztna-pop
sudo systemctl status ztna-pop

# Ou si lancé manuellement :
sudo ./ztna-pop \
  --pop-id <TON_POP_ID> \
  --control-plane http://176.136.202.205:8080 \
  --wg-interface wg0 \
  --wg-port 51820 \
  --heartbeat 30
```

### Option 2 : Si tu n'as pas Git sur le VPS

```bash
# Télécharger le code depuis GitHub
cd ~
rm -rf ztna-sovereign  # Si le dossier existe déjà
git clone <URL_DE_TON_REPO> ztna-sovereign
cd ztna-sovereign

# Compiler le PoP
go build -o ztna-pop ./cmd/pop

# Arrêter l'ancien PoP
pkill ztna-pop

# Relancer le PoP
sudo ./ztna-pop \
  --pop-id <TON_POP_ID> \
  --control-plane http://176.136.202.205:8080 \
  --wg-interface wg0 \
  --wg-port 51820 \
  --heartbeat 30
```

### Option 3 : Télécharger juste le binaire compilé

Si tu as compilé sur Windows, tu peux transférer le binaire :

```bash
# Sur Windows, après compilation
# Le binaire est dans : ztna-sovereign/ztna-pop

# Transférer via SCP depuis Windows PowerShell :
# scp ztna-pop ubuntu@<IP_VPS>:/tmp/ztna-pop

# Puis sur le VPS :
sudo mv /tmp/ztna-pop /usr/local/bin/ztna-pop
sudo chmod +x /usr/local/bin/ztna-pop

# Arrêter l'ancien PoP
pkill ztna-pop

# Relancer
sudo ztna-pop \
  --pop-id <TON_POP_ID> \
  --control-plane http://176.136.202.205:8080 \
  --wg-interface wg0 \
  --wg-port 51820 \
  --heartbeat 30
```

## Vérification après mise à jour

### 1. Vérifier que le PoP démarre correctement

```bash
# Voir les logs
sudo journalctl -u ztna-pop -f
# ou si lancé manuellement, voir la sortie
```

Tu devrais voir :
```
[PoP:...] Peer added: ... (AllowedIPs: [192.168.75.0/24 100.65.0.0/16])
```

### 2. Vérifier WireGuard

```bash
sudo wg show wg0
```

Tu devrais voir le connecteur comme peer avec les AllowedIPs corrects.

### 3. Tester le routage

```bash
ping -c 3 192.168.75.130
```

Ça devrait fonctionner maintenant !

## Créer un service systemd (recommandé)

Pour que le PoP démarre automatiquement :

```bash
sudo nano /etc/systemd/system/ztna-pop.service
```

Contenu :
```ini
[Unit]
Description=ZTNA Sovereign PoP Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ztna-pop \
  --pop-id <TON_POP_ID> \
  --control-plane http://176.136.202.205:8080 \
  --wg-interface wg0 \
  --wg-port 51820 \
  --heartbeat 30
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Puis :
```bash
sudo systemctl daemon-reload
sudo systemctl enable ztna-pop
sudo systemctl start ztna-pop
sudo systemctl status ztna-pop
```

## Troubleshooting

### Le PoP ne reçoit pas les peers

1. Vérifie que le PoP est bien enregistré dans le dashboard
2. Vérifie que le connecteur est assigné au bon PoP
3. Vérifie les logs du PoP pour voir les erreurs

### Les routes ne fonctionnent toujours pas

1. Vérifie que le forwarding IP est activé :
   ```bash
   sysctl net.ipv4.ip_forward
   # Doit être à 1
   ```

2. Vérifie les règles iptables :
   ```bash
   sudo iptables -L FORWARD -n -v
   ```

3. Vérifie WireGuard :
   ```bash
   sudo wg show wg0
   ```
