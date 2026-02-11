# Signature de Code pour Windows

Pour éviter l'avertissement "Téléchargement dangereux" sur Windows, il faut signer le binaire avec un certificat de code signing.

## Solution Rapide (Développement)

Pour le développement, vous pouvez ignorer l'avertissement Windows. Les utilisateurs peuvent cliquer sur "Plus d'infos" puis "Exécuter quand même".

## Solution Production (Certificat de Code Signing)

### 1. Acheter un Certificat

**Recommandé** : Certificat EV (Extended Validation) - ~$200-400/an
- **Sectigo (ex-COMODO)** : https://sectigo.com/ssl-certificates-tls/code-signing
- **DigiCert** : https://www.digicert.com/code-signing/
- **GlobalSign** : https://www.globalsign.com/en/code-signing-certificate

**Alternative** : Certificat OV (Organization Validation) - ~$100-200/an
- Moins cher mais Windows SmartScreen peut encore afficher un avertissement

### 2. Installer le Certificat

1. Télécharger le certificat depuis le fournisseur (fichier `.pfx` ou `.p12`)
2. Double-cliquer sur le fichier pour l'installer dans le magasin de certificats Windows
3. Entrer le mot de passe fourni

### 3. Signer le Binaire

```powershell
# Trouver le certificat
Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert

# Signer avec signtool (Windows SDK)
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com ztna-agent-fyne.exe

# Ou avec PowerShell (Windows 10+)
Set-AuthenticodeSignature -FilePath ztna-agent-fyne.exe -Certificate (Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert)
```

### 4. Vérifier la Signature

```powershell
signtool verify /pa ztna-agent-fyne.exe
```

## Alternative : Certificat Auto-Signé (Test)

Pour les tests, vous pouvez créer un certificat auto-signé :

```powershell
# Créer un certificat auto-signé (nécessite admin)
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=ZTNA Sovereign" -CertStoreLocation Cert:\CurrentUser\My

# Exporter en .pfx
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
$password = ConvertTo-SecureString -String "MyPassword123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath ztna-cert.pfx -Password $password

# Signer
signtool sign /f ztna-cert.pfx /p MyPassword123! /t http://timestamp.digicert.com ztna-agent-fyne.exe
```

**Note** : Windows affichera quand même un avertissement pour les certificats auto-signés, mais c'est mieux que rien.

## Intégration dans le Build

### Script PowerShell

Créez `scripts/sign-binary.ps1` :

```powershell
param(
    [string]$BinaryPath,
    [string]$CertPath,
    [string]$CertPassword
)

# Vérifier que signtool existe
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    Write-Error "signtool not found. Install Windows SDK."
    exit 1
}

# Signer
& $signtool sign /f $CertPath /p $CertPassword /t http://timestamp.digicert.com $BinaryPath

# Vérifier
& $signtool verify /pa $BinaryPath
```

### GitHub Actions

```yaml
- name: Sign Windows binary
  run: |
    $cert = Get-Content "${{ secrets.CODE_SIGNING_CERT }}" | ConvertFrom-Json
    $certBytes = [Convert]::FromBase64String($cert.data)
    $certPassword = ConvertTo-SecureString $cert.password -AsPlainText -Force
    Import-PfxCertificate -FilePath $certBytes -CertStoreLocation Cert:\CurrentUser\My -Password $certPassword
    signtool sign /f $certBytes /p $cert.password /t http://timestamp.digicert.com ztna-agent-fyne.exe
```

## Coûts

- **Certificat EV** : ~$200-400/an (recommandé pour production)
- **Certificat OV** : ~$100-200/an (moins cher mais moins fiable)
- **Certificat auto-signé** : Gratuit (développement/test uniquement)

## Références

- [Microsoft Code Signing](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools)
- [Windows SmartScreen](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview)
