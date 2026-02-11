# Compilation de l'Agent Fyne (Interface Native)

L'agent Fyne est une version native Windows de l'agent ZTNA avec une interface graphique native (pas de navigateur).

## Prérequis pour la Compilation

### Windows (compilation locale)
1. **Go 1.24+** : https://go.dev/dl/
2. **TDM-GCC** ou **MinGW-w64** (pour CGO) : https://jmeubank.github.io/tdm-gcc/ ou https://www.mingw-w64.org/
3. **CGO activé** : `set CGO_ENABLED=1`

### Linux/macOS (cross-compilation)
1. **Go 1.24+**
2. **CGO activé** : `export CGO_ENABLED=1`
3. **Cross-compilation toolchain** pour Windows

## Compilation

### Option 1 : Compilation locale (Windows)

```powershell
# Installer TDM-GCC ou MinGW-w64
# Puis :
$env:CGO_ENABLED=1
go build -o ztna-agent-fyne.exe ./cmd/agent-fyne
```

### Option 2 : Cross-compilation depuis Linux/macOS

```bash
# Installer mingw-w64
# Ubuntu/Debian:
sudo apt install gcc-mingw-w64

# macOS:
brew install mingw-w64

# Compiler:
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o ztna-agent-fyne.exe ./cmd/agent-fyne
```

### Option 3 : Docker (recommandé)

Le Dockerfile API cross-compile déjà l'agent Fyne :

```bash
docker-compose build api
docker cp $(docker-compose ps -q api):/var/lib/ztna/downloads/ztna-agent-fyne-windows-amd64.exe .
```

## Signature du Binaire (Éviter l'Avertissement Windows)

Windows affiche un avertissement "Téléchargement dangereux" pour les exécutables non signés. Pour l'éviter :

### Option A : Certificat de Code Signing (Recommandé pour Production)

1. **Acheter un certificat de code signing** :
   - Sectigo (ex-COMODO) : ~$200/an
   - DigiCert : ~$400/an
   - GlobalSign : ~$300/an

2. **Signer le binaire** :
```powershell
# Installer signtool (inclus dans Windows SDK)
# Puis :
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com ztna-agent-fyne.exe
```

### Option B : Certificat Auto-Signé (Développement/Test)

```powershell
# Créer un certificat auto-signé (nécessite admin)
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=ZTNA Sovereign" -CertStoreLocation Cert:\CurrentUser\My

# Exporter le certificat
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
Export-PfxCertificate -Cert $cert -FilePath ztna-cert.pfx -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)

# Signer le binaire
signtool sign /f ztna-cert.pfx /p password /t http://timestamp.digicert.com ztna-agent-fyne.exe
```

**Note** : Windows affichera quand même un avertissement pour les certificats auto-signés, mais c'est mieux que rien.

### Option C : Ajouter au Build Docker

Ajouter la signature dans le Dockerfile :

```dockerfile
# Dans Dockerfile.api, après la compilation :
RUN apt-get update && apt-get install -y osslsigncode
COPY ztna-cert.pfx /tmp/
RUN osslsigncode sign -pkcs12 /tmp/ztna-cert.pfx -pass password -in /binaries/ztna-agent-fyne-windows-amd64.exe -out /binaries/ztna-agent-fyne-windows-amd64-signed.exe
```

## Distribution

1. **Télécharger depuis le Control Plane** : L'agent Fyne sera disponible dans `/api/downloads/agent-fyne/windows`
2. **GitHub Releases** : Uploader le binaire signé dans les releases GitHub
3. **Site web** : Héberger le binaire signé sur votre site

## Notes

- **WireGuard** : L'agent Fyne utilise la même logique WireGuard que l'agent web. WireGuard doit être installé une fois sur Windows (inclut wintun).
- **Interface native** : L'agent Fyne utilise Fyne v2 pour une interface graphique native Windows (pas de navigateur).
- **Taille** : Le binaire fait ~15-20 MB (inclut Fyne + toutes les dépendances).
