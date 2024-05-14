# De bons croissants au beurre

Difficile 995 

Le nouveau dev junior en charge du site de l'association de tir à l'arc ne fait rien depuis qu'il est revenu de vacances mercredi... Il a réinstallé tout son ordinateur en disant que ça allait le rendre plus productif et hyper sécurisé, mais en attendant, il ne fait qu'éditer des configurations et rien d'autre. Et il n'a même pas encore configuré le verrouillage de son écran ! On s'en est rendu compte parce que quelqu'un a visiblement profité de sa pause déjeuner pour lui faire une farce. Lui dit que ça va plus loin et dit qu'on lui a mis une porte dérobée sur son PC... Il parle de session sudo encore active, de logs supprimés ou je ne sais quoi... A tel point que le RSSI inquiet a fait une image de son disque.

Pourrez-vous trouver la porte dérobée et analyser son fonctionnement ?

Le flag est au format habituel : 404CTF{...}.

MD5 AlexisLaptop.7z : 0eb7108316f318224269aece103eb6d6

Auteur: @Smyler


## Analyse initiale

Un premier indices dans l'énoncé : https://github.com/AlexisGerard98/AlexisGerard98/tree/b67a78189b89be29390ddd0197878905adeebeec 

Date du commit: 2024-02-21T13:48:51.000+01:00

L'image disque est accompagnée d'une photo contenant une "recovery key" générée lors du chiffrement du disque avec `systemd-cryptenroll`

`dflnrftl-dghdcdcc-uljjvtdi-grrvdnne-lveeegci-bclknhtf-jgrikeui-glfbdfru`

L'archive contient un fichier texte qui semble avoir été généré par un outils forensic.

Une recherche "ADI3" nous amène ici : https://miguelbigueur.com/2017/04/08/usb-forensics/
= "Image Summary output from FTK Imager"

L'outil utilisé semble être FTK Imager, Téléchargement et installation de FTK Imager

L'ouverture de l'image fonctionne mais seule la partition boot FAT16 s'affiche !

La partition système est vue comme "Unrecognized file system [Linux Root (x86-64)]

L'entête du fichier .s0 contient le mot clé "LUKS" : https://fr.wikipedia.org/wiki/LUKS

> LUKS permet de chiffrer l'intégralité d'un disque de telle sorte que celui-ci soit utilisable sur d'autres plates-formes et distributions de Linux (voire d'autres systèmes d'exploitation). Il supporte des mots de passe multiples, afin que plusieurs utilisateurs soient en mesure de déchiffrer le même volume sans partager leur mot de passe.

Le fichier est reconnu comme "EWF/Expert Witness/EnCase image file format"
```
$ file AlexisLaptop.s01
AlexisLaptop.s01: EWF/Expert Witness/EnCase image file format
```


## Montage et déchiffrement de l'image disque :

```
$ ewfmount AlexisLaptop.s01 /mnt/ewf 
ewfmount 20140814
```

On obtient alors une image disque brute : `/mnt/ewf/ewf1`

```
$ file /mnt/ewf/ewf1
ewf1: DOS/MBR boot sector; partition 1 : ID=0xee, start-CHS (0x0,0,2), end-CHS (0x3ff,255,63), startsector 1, 16777215 sectors, extended partition table (last)
```

On attache l'image disque brute à un device loop :

```
$ losetup -Pf --show /mnt/ewf/ewf1                           
/dev/loop0
```

Ce qui nous donne 2 partitions : boot et os

```
$ ls /dev/loop0p*
/dev/loop0p1  /dev/loop0p2
```

Déchiffrement du volume :

```
$ cryptsetup luksOpen /dev/loop0p2 decrypted_volume
Could not find TPM2 device: Operation not supported
Enter passphrase for /dev/loop1p2: dflnrftl-dghdcdcc-uljjvtdi-grrvdnne-lveeegci-bclknhtf-jgrikeui-glfbdfru
```

```
$ ls /dev/mapper/*
/dev/mapper/control  /dev/mapper/decrypted_volume
```                                                                                                                     

Montage du volume déchiffré :

```                                   
$ mount /dev/mapper/decrypted_volume /mnt/decrypted 
mount: /mnt/decrypted: WARNING: source write-protected, mounted read-only.
```

## Analyse du système de fichiers

Le volume semble contenir les données d'un disque systeme linux dans le dossier `/@` ainsi que des snapshots dans le dossier `/timeshift-btrfs/snapshots/2024-*`.

L'analyse du fichier history, avec horodatage, nous donne pas mal d'info :

https://www.epochconverter.com/

```
: 1708502803:0;cd Projects/lablonde-dictionnaire
: 1708502804:0;ls
: 1708502813:0;vim astro.config.mjs
: 1708510668:0;vim src/pages/index.astro
: 1708515387:0;swayidle
: 1708519185:0;sudo pacman -Sy pavucontrol
: 1708519211:0;pavucontrol
: 1708519405:0;sudo 
: 1708519406:0;sudo id
: 1708519408:0;sudo -l
: 1708519411:0;sudo -s
: 1708519585:0;reset
: 1708519587:0;pav
: 1708519589:0;pavucontrol
: 1708519888:0;history
: 1708519911:0;shutdown now
```

L'attaquant a fait vite, il ne semble être resté connecté 5 minutes, ce qui laisse pas le temps de faire beaucoup de choses.

Rien dans l'historique des commandes root.

Rien dans les logs.

Recherche de tous les fichiers créés ou modifiés après mercredi 21 février 2024 13:43:31 : 

```
find /mnt/decrypted -type f -newermt @1708381411 ! -newermn @1708519585
```

Plusieurs packages pacman installés : 

```
/mnt/decrypted/@/var/lib/pacman/local/tdb-1.4.9-1/desc
/mnt/decrypted/@/var/lib/pacman/local/tdb-1.4.9-1/files
/mnt/decrypted/@/var/lib/pacman/local/sound-theme-freedesktop-0.8-5/desc
/mnt/decrypted/@/var/lib/pacman/local/sound-theme-freedesktop-0.8-5/files
/mnt/decrypted/@/var/lib/pacman/local/libcanberra-1:0.30+r2+gc0620e4-3/desc
/mnt/decrypted/@/var/lib/pacman/local/libcanberra-1:0.30+r2+gc0620e4-3/files
/mnt/decrypted/@/var/lib/pacman/local/pavucontrol-1:5.0+r64+geba9ca6-1/desc
/mnt/decrypted/@/var/lib/pacman/local/pavucontrol-1:5.0+r64+geba9ca6-1/files
/mnt/decrypted/@/var/lib/pacman/local/wget-1.21.4-1/desc
/mnt/decrypted/@/var/lib/pacman/local/wget-1.21.4-1/files
/mnt/decrypted/@/var/lib/pacman/local/pam-1.6.0-3/desc
/mnt/decrypted/@/var/lib/pacman/local/pam-1.6.0-3/files
```

Installation de wget + traces de données en cache : 

```
cat /mnt/decrypted/@/root/.wget-hsts
# HSTS 1.0 Known Hosts database for GNU Wget.
# Edit at your own risk.
# <hostname>	<port>	<incl. subdomains>	<created>	<max-age>
t.ly	0	1	1708519519	15552000
```

```
sudo find /mnt/decrypted -type f -readable ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" -exec grep -H 'https://t.ly' {} +
```

(...)


**Timeline :**

* mercredi 21 février 2024 13:43:25 GMT+01:00 sudo
* mercredi 21 février 2024 13:43:31 GMT+01:00 sudo -s => **root**
* mercredi 21 février 2024 13:45:19 GMT+01:00 téléchargement d'un fichier via lien "t.ly"
* mercredi 21 février 2024 13:45:33 GMT+01:00 **snapshot**
* mercredi 21 février 2024 13:46:25 GMT+01:00 reset
* mercredi 21 février 2024 13:48:51 GMT+01:00 commit
* mercredi 21 février 2024 13:51:51 GMT+01:00 shutdown

Par chance un snapshot a été fait juste après le wget :)

**NOTE**: L'auteur du chall m'a apporté une précision : "Pas vraiment par chance : https://aur.archlinux.org/packages/timeshift-autosnap (...) l'installation de la backdoor à trigger la création du snapshot"

Recherche des différences entre les données actuelles et celle du snapshot de 13h45.

```
diff -r timeshift-btrfs/snapshots/2024-02-21_13-45-33/@ @ > /mnt/lab/404ctf/forensic-hdd/diff_13-45-33.txt
```

8 fichiers ont été modifiés

Le fichier `/root/1QoOr` est le fichier téléchargé par l'attaquant.

```
file /mnt/decrypted/timeshift-btrfs/snapshots/2024-02-21_13-45-33/@/root/1QoOr
/mnt/decrypted/timeshift-btrfs/snapshots/2024-02-21_13-45-33/@/root/1QoOr: Zstandard compressed data (v0.8+), Dictionary ID: None
```

```
cp timeshift-btrfs/snapshots/2024-02-21_13-45-33/@/root/1QoOr /dev/shm
cd /dev/shm                                                           
tar -xvf 1QoOr
```

Il s'agit d'un package pacman PAM "troué" !

```
cat .PKGINFO 

# Generated by makepkg 6.0.2
# using fakeroot version 1.33
pkgname = pam
pkgbase = pam
pkgver = 1.6.0-3
pkgdesc = Backdoor by XxX_31337_h@x0r_XxX. Good luck figuring out how it works :p
builddate = 1707935249
packager = Unknown Packager
size = 3396410
arch = x86_64
license = GPL2
provides = libpam.so=0-64
provides = libpamc.so=0-64
provides = libpam_misc.so=0-64
```

Analyses des fichiers implantés (B) vs les fichiers originaux (G):

```
/lib/security/pam_unix.so
/lib64/security/pam_unix.so
B=1b552c11453d3b51a972ec383218a225, G=4b2b29efd6608262238d11d448300e48

/var/lib/pacman/local/pam-1.6.0-3/mtree     
B=5428f290a45a1784052b259a0f22334c, G=67c31a157b5c12373759e35a82f5cc98
```

Décompilation du code source de la librairie `pam_unix.so` modifiée et originale via gHidra.

Récupération des sources originales : https://mirrors.mit.edu/archlinux/sources/packages/pam-1.6.0-3.src.tar.gz

La comparaison du code C décompilé des binaires est longue et fastidieuse.. mais porte ses fruits.

Le code malicieux a été injecté dans la fonction `_unix_verify_password` :


```c
  do {
    if (p[lVar4] == 0) break;
    lVar9 = lVar4 + 1;
    bVar15 = bVar15 | p[lVar4] ^ *(byte *)((long)&local_2c8 + lVar4) ^
                      *(byte *)((long)&local_328 + (ulong)((uint)lVar4 & 0x1f));
    lVar4 = lVar9;
  } while (lVar9 != 0x3e);
  if ((bVar15 == 0) || (bVar14)) {
    retval = 0;
  }
```

La fonction semble effectuer des opérations XOR pour chaque caractère du mot de passe avec les données de 2 variables.

La déclaration des variables obtenue via la décompilation ghidra est étrange compliquée à comprendre.

```
  local_328 = 0x6f5f4577;
  uStack_324 = 0x9688907c;
  uStack_320 = 0x4705b114;
  uStack_31c = 0x1b4e8e33;
  local_318 = 0x1032828b8af8070a;
  uStack_310 = 0x5fbb2a55;
  uStack_30c = 0x1c3fc671;
  local_2c8 = 0xf2f3d6282c6b7543;
  uStack_2c0 = 0x770fd15d7631dc27;
  local_2b8 = 0x7654b2d4bf917f39;
  uStack_2b0 = 0x2ce44f27;
  uStack_2ac = 0x6c60881e;
  local_2a8 = 0x11f3644;
  uStack_2a4 = 0xf3cccf08;
  uStack_2a0 = 0x7777d24b;
  uStack_29c = 0x7a3dfd5a;
  uStack_298 = 0x6dd7ead58b3044;
  uStack_291 = 0xbb342dc95f6672;
```

En assembleur, c'est "plus clair" : 

```
    MOVAPS     xmmword ptr [RSP + local_328[0]],XMM0
    MOVDQA     XMM0,xmmword ptr [DAT_0010a0b0]                  = 0Ah
    MOVAPS     xmmword ptr [RSP + local_318[0]],XMM0
    MOVDQA     XMM0,xmmword ptr [DAT_0010a0c0]                  = 43h    C
    MOVAPS     xmmword ptr [RSP + local_2c8[0]],XMM0
    MOVDQA     XMM0,xmmword ptr [DAT_0010a0d0]                  = 39h    9
    MOVAPS     xmmword ptr [RSP + local_2b8[0]],XMM0
    MOVDQA     XMM0,xmmword ptr [DAT_0010a0e0]                  = 44h    D
    MOVAPS     xmmword ptr [RSP + local_2a8[0]],XMM0
    MOVDQA     XMM0,xmmword ptr [DAT_0010a0f0]                  = 7Ah    z
    MOVUPS     xmmword ptr [RSP + local_2a8[15]],XMM0
```

Bref, j'arrive en extraire ça :

```py
local_328 = 0x0a07f88a8b823210552abb5f71c63f1c
local_318 = 0x43756b2c28d6f3f227dc31765dd10f77
local_2c8 = 0x397f91bfd4b25476274fe42c1e88606c
local_2b8 = 0x44361f0108cfccf34bd277775afd3d7a
local_2a8 = 0x7a44308bd5ead76d72665fc92d34bb00
local_xxx = 0x77455f6f7c90889614b10547338e4e1b
```

L'analyse du code assembleur de la fonction apporte également plus d'éléments :

```
LAB_001059e8
    MOV        var_1,p
    XOR        _var_len_1,byte ptr [p + var_2*0x1]
    ADD        p,0x1
    AND        var_1,0x1f
    XOR        _var_3,byte ptr [RSP + var_1*0x1 + 0xc0]
    OR         ctrl,_var_3
    CMP        p,0x3e
    JZ         LAB_00105a0d
LAB_00105a04
    MOVZX      _var_3,byte ptr [R15 + p*0x1]
    TEST       _var_3,_var_3
    JNZ        LAB_001059e8
```

Ayant globalement compris le fonctionnement de la fonction, c'est l'heure de brute forcer !

```py
class forcer():
    def __init__(self, l1,l2):
        self.l1 = l1
        self.l2 = l2
        self.value = ["." for i in range(0,16)]
        self.chars = {}
    def __repr__(self):
        return f"({self.l1},{self.l2}) [{''.join(self.value)}] {len(self.chars)}"

def brute(l1,l2,d=0,s="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_!{}@"):
    job = jobs.get((l1,l2))
    if job == None:
        job = forcer(l1,l2)
        jobs[(l1,l2)] = job
    for c in s:
        iy = d
        for ix, x in enumerate(locals[l1]):
            y = locals[l2][iy]
            r = ord(c) ^ x ^ y
            if r == 0:
                job.value[ix] = c
                job.chars[c] = 1 if job.chars.get(c) == None else job.chars[c] + 1
            iy = 0 if iy == len(locals[l2])-1 else iy+1

locals = {}
l_strings = {}
jobs = {}

def addLocal(o,s):
    l_strings[o] = s
    locals[o] = []
    for i in range(0,len(s),2):
        locals[o].append(int(s[i:i+2],16))

addLocal('328', "0a07f88a8b823210552abb5f71c63f1c")
addLocal('318', "43756b2c28d6f3f227dc31765dd10f77")
addLocal('2c8', "397f91bfd4b25476274fe42c1e88606c")
addLocal('2b8', "44361f0108cfccf34bd277775afd3d7a")
addLocal('2a8', "7a44308bd5ead76d72665fc92d34bb00")
addLocal('xxx', "77455f6f7c90889614b10547338e4e1b")

for ilx in locals:
    for ily in locals:
        if ilx == ily: continue
        for z in range(0,16):
            brute(ilx, ily, d=z)
            for job in jobs:
                if len(jobs[job].chars) > 9:
                    print(jobs[job], z)
            jobs = {}
```

```
python pam_unix/bkdo-force.py 
(328,2c8) [3xi5_0ffre_soN_p] 13 0
(328,2a8) [N7s_aU_b3urrE}.f] 13 1
(318,xxx) [404CTF{d3m41n_Al] 14 0
(2c8,328) [3xi5_0ffre_soN_p] 13 0
(2b8,xxx) [3s@nt_De_cr0issa] 13 0
(2a8,328) [fN7s_aU_b3urrE}.] 13 15
(xxx,318) [404CTF{d3m41n_Al] 14 0
(xxx,2b8) [3s@nt_De_cr0issa] 13 0
```

> d3m41n_Al3xi5_0ffre_soN_p3s@nt_De_cr0issaN7s_aU_b3urrE





