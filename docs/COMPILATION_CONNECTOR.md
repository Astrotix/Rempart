# 🔨 Compilation du Connecteur

## Pourquoi recompiler ?

Les modifications apportées permettent au connecteur de :
- Sauvegarder ses clés WireGuard dans un fichier
- Réutiliser les clés sauvegardées au redémarrage
- Se reconnecter avec le même token sans erreur

**Tu dois recompiler le connecteur** pour bénéficier de ces améliorations.

---

## Compilation sur Linux (serveur du connecteur)

### Option 1 : Compiler directement sur le serveur

```bash
# 1. Cloner ou récupérer le repo
git clone <URL_DU_REPO> ztna-sovereign
cd ztna-sovereign

# Ou si tu as déjà le repo, mettre à jour
cd ztna-sovereign
git pull

# 2. Compiler le connecteur
go build -o ztna-connector ./cmd/connector

# 3. Rendre exécutable
chmod +x ztna-connector

# 4. Tester
./ztna-connector --help
```

### Option 2 : Cross-compiler depuis Windows (si tu as Go installé)

Sur ton PC Windows :

```powershell
# Aller dans le répertoire du projet
cd "C:\Users\guill\Downloads\Site Eric\ztna-sovereign"

# Cross-compiler pour Linux amd64
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o ztna-connector-linux-amd64 ./cmd/connector

# Transférer le binaire sur le serveur (via SCP, SFTP, etc.)
# scp ztna-connector-linux-amd64 user@server:/path/to/ztna-connector
```

---

## Compilation depuis le Docker (si le Control Plane est dans Docker)

Si tu veux compiler depuis le container Docker de l'API :

```bash
# Entrer dans le container
docker exec -it docker-api-1 sh

# Compiler (si Go est installé dans le container)
go build -o /tmp/ztna-connector ./cmd/connector

# Copier le binaire hors du container
docker cp docker-api-1:/tmp/ztna-connector ./ztna-connector
```

---

## Vérification après compilation

Une fois le nouveau binaire compilé :

1. **Remplace l'ancien binaire** sur le serveur du connecteur
2. **Supprime l'ancien fichier de clés** (optionnel, pour forcer une nouvelle activation) :
   ```bash
   rm -f /etc/ztna/connector-keys.json
   rm -f ./connector-keys.json
   ```
3. **Lance le connecteur** avec le même token :
   ```bash
   sudo ./ztna-connector \
     --token <TON_TOKEN> \
     --control-plane http://176.136.202.205:8080 \
     --networks 192.168.75.0/24
   ```

---

## Différences avec l'ancien binaire

L'ancien binaire :
- ❌ Génère de nouvelles clés à chaque démarrage
- ❌ Ne peut pas réutiliser le token après la première activation
- ❌ Erreur 401 si tu redémarres

Le nouveau binaire :
- ✅ Sauvegarde les clés dans un fichier
- ✅ Réutilise les clés au redémarrage
- ✅ Peut se reconnecter avec le même token
- ✅ Fonctionne après redémarrage du serveur

---

## Fichier de clés sauvegardé

Le connecteur sauvegarde ses clés dans :
- `/etc/ztna/connector-keys.json` (si accessible)
- `./connector-keys.json` (sinon, dans le répertoire courant)

**Important :** Ce fichier contient la clé privée WireGuard. Protège-le :
```bash
chmod 600 connector-keys.json
chown root:root connector-keys.json  # Si lancé en root
```

---

## Si tu n'as pas accès au repo Git

Si tu ne peux pas récupérer le code depuis Git, tu peux :

1. **Copier le binaire compilé** depuis ton PC Windows vers le serveur
2. **Ou compiler directement sur le serveur** si Go est installé

Le binaire compilé est autonome et n'a pas besoin de dépendances supplémentaires.
