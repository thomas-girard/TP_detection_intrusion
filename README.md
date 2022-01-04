# TP_detection_intrusion

Les règles sont dans /var/lib/suricata/rules/suricata.rules

fichier de configuration : /etc/suricata/suricata.yaml

Les logs dans sont var/log/suricata


## 3.1

* sudo suricata-update enable-source et/open

* Suricata est lent, c'est normal

* Suricata : on peut mettre plus de RAM, enlever les règles

* les logs de Suricata sont dans var/log/suricata

* Alertes générées par nmap :
    * on a des alertes de type "ET SCAN NMAP" et "ET SCAN" dans fast.log. On a tout d'bord la date et l'heure de l'alerte, puis le type de la signature avec une classification en terme de dangerosité, ici on a par exemple "classification attempted information leak" de priorité 2. Enfin, on nous informe sur le type de protocole du paquet (ici TCP), ainsi que l'IP source et l'IP destination.
    * comment le scan est détecté ? cf capture écran + dans les règles, il y a par exemple la signature "ET SCAN NMAP -sS window 4096" et cette signature est répérée lors du scan nmap





    * dans fast.log : on retrouve les alertes nmap.
    * les alertes sont classifiées "


## 3.2

* Cette signature correspond à des paquets de type "http" du réseau interne vers le réseau externe de type "post" et qui correspond au minage de bitcoin.
* Cette alerte permet de détecter le minage de cryptomonnaie  : elle recherche la chaine de caractère "x mining-extension" en ascii suivi de l'octet "3a" dans les headers http d'une requête post. Cette alerte détecte si un attaquant passe des informations dans le headers http (si c'était un minage de cryptomonnaie légal, cela ne serait pas dans le header, mais dans le content)

* Pour générer l'alerte : "curl -X POST --header "X-Mining-Extensions:mining" 192.168.6.2" depuis le serveur et en lançant "apache2ctl start" depuis backtrack.

* Cette alerte n'est pas le signe direct qu'un intruison puisqu'il s'agit d'une requête depuis le réseau internet vers le réseau externe. Cependant, si de telles requêtes sont détectées, cela signifie qu'en amont, il y a eu une intrusion, le serveur a été compromis.

* Les logs nous indique que l'alerte est de type "Crypto Currency Mining Activity Detected"

## 3.3

* On lance buggy avec ./buggy dans /root/buggyhttp.
* Avec la requête curl vide depuis backtrack, on obtient une réponse "empty reply from server"
* Avec la requête "curl 192.168.5.2:7979/../../../../../etc/shadow" on récupère les mots de passe sous forme de hash.


* alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Password file leak!";
content:"/etc/shadow";sid:1000001;)

* Fonctionnement de cette règle : elle fait du pattern matching de "xxx" avec le content de la requête http vers n'importe quel serveur du réseau externe.

* Cete règle fonctionne.

* Pour ajouter la classification, "Attempted information leak", on ajoute à la signature : "classtype:attempted-recon" : credentials-theft

* Pour restreindre l'application aux flux pertinents, on ajoute [$HOME_NET, $HTTP_SERVERS]

* Pour le suivi d'etat, on ajoute " flow:established"








## Note

* Elastic : enlever port 9243 dans l'url
* syslog pas tcp que udp "@ nom host + adresse ip" et pas de port

## Rapport TP : 

https://docs.google.com/document/d/1KyPuZO2iMvVPAw2-JdoelhmfSNIDyv-Au7bPT9Xuitk/edit?usp=sharing



