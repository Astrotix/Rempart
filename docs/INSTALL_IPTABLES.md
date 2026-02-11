# 🔧 Installation d'iptables sur Ubuntu/Debian

Si tu vois l'erreur `iptables: command not found`, il faut installer iptables.

## Installation

```bash
# Mettre à jour les paquets
sudo apt update

# Installer iptables
sudo apt install -y iptables

# Vérifier l'installation
sudo iptables --version
```

## Alternative : iptables-nft

Sur certaines versions récentes d'Ubuntu, iptables peut être remplacé par `iptables-nft`. Vérifie :

```bash
# Vérifier si iptables-nft est disponible
which iptables-nft

# Si oui, créer un lien symbolique
sudo ln -s /usr/sbin/iptables-nft /usr/sbin/iptables
```

## Vérification

Après installation, vérifie que ça fonctionne :

```bash
# Lister les règles
sudo iptables -L -n -v

# Vérifier les règles FORWARD
sudo iptables -L FORWARD -n -v
```

## Redémarrer le connecteur

Une fois iptables installé, redémarre le connecteur pour qu'il configure les règles :

```bash
# Arrêter le connecteur (Ctrl+C si en mode interactif)
# Puis relancer
sudo ./ztna-connector \
  --token <TON_TOKEN> \
  --control-plane http://176.136.202.205:8080 \
  --networks 192.168.75.0/24
```

Le connecteur devrait maintenant configurer correctement les règles iptables et les logs de trafic devraient apparaître.
