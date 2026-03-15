# About This Project

Hi everyone, my name is Luca and this is my first Claude Opus 4.6 project.

I needed some VoIP login information from a FritzBox backup — and that is how it started.

PS: This specific file is the ONLY one written by myself! BUT: layouted and corrected by Claude. 

---

## How It Began

Out of curiosity I also launched a web service running this script:
**[www.fb-decoder.com](https://www.fb-decoder.com)**

The server has been set up entirely by Claude via SSH. I just provided a freshly
installed Debian Trixie VPS with no other prior purpose.

---

## Full Transparency — My Initial Prompts

For full transparency, here are the exact prompts I used to kick things off.

**Script**

> *hier ist ein backup file der fritzbox \*.export. es ist mit dem passwort [redacted]
> verschlüsselt. analysiere es bitte und extrahiere mir vor allem die telefonie daten (VoIP). danke*

**Web Service**

> *In dem Ordner Python findest du das Programm FritzBox-Backup-Decoder und eine Readme.
> Ich möchte dass du mir in dem Ordner Web eine Webversion baust, also einen Onlinedienst.
> Der Server wird ein schlichter VPS sein, eine Kombination aus nginx und Python, Debian Trixie.
> Die Startseite puristisch, ein Upload-Feld, und der User bekommt die JSON- und TXT-Datei
> als ZIP-Download angeboten.*
>
> *Achte darauf, dass das Tool auch auf Handy und Tablets gut benutzbar ist. Das Design
> ist insgesamt sehr minimalistisch — bitte hell und einladend halten.*
>
> *Impressum auch vorbereiten und eine Seite, auf welcher wir darstellen, dass wir keinerlei
> Nutzerdaten speichern und loggen und lediglich temporär im RAM vorhalten. Nur bei
> explizitem Analysewunsch werden Daten bis zum Abschluss der Analyse vorgehalten und
> anschließend gelöscht.*
>
> *Weise auch darauf hin, dass dieses Tool nur für eigene Exports genutzt werden darf und
> nicht, um Zugriff auf Daten fremder FritzBoxen zu erhalten. Stelle auch heraus, dass es
> sich bei dem Tool lediglich um einen Decryptor, nicht aber um einen Passwort-Cracker handelt.*
>
> *Im Backend bitte einen Log mit anonymisierten IPs (versuche zu jeder IP auch die
> Geolocation zu extrahieren, bevor du sie anonymisierst) und dem dazu hochgeladenen
> Dateinamen. Sollte das Tool beim Entschlüsseln oder während der Laufzeit Fehler ausgeben,
> vermerke das im Frontend — aber gib keine klare Fehlermeldung aus. Der klare Fehler soll
> nur im Backend-Log ersichtlich sein.*
>
> *Gib den Nutzern auch die Möglichkeit, Dateien zur Analyse und Weiterentwicklung des Tools
> einzusenden (auf einer separaten Seite, gib dort aber auch eine Warnung aus, dass hier
> sensible Daten temporär gespeichert werden).*
>
> *Im normalen Use-Case — also reines und direktes Entschlüsseln — bitte ich dich, das Tool
> so zu gestalten, dass möglichst KEINE Dateien auf die lokale Festplatte geschrieben werden.
> Der Dienst muss so anonym wie irgend möglich operieren: User lädt Export hoch, intern wird
> die Datei im RAM vorgehalten, bearbeitet, und aus dem RAM heraus werden die extrahierten
> Daten in eine ZIP-Datei gepackt (die auch nur temporär im RAM liegt) und umgehend dem
> User zum Download zur Verfügung gestellt. Nach abgeschlossenem Download werden die
> hochgeladenen Daten sowie die Ergebnisse umgehend gewiped.*
>
> *Liefere auch eine nginx-Config, die IPs im Zugriff anonymisiert. Härte nginx und das
> Backend generell gegen Angriffe nach Best Practice.*
>
> *Bedenke, dass es passieren kann, dass mehrere User gleichzeitig Daten bearbeiten — das
> Tool muss das verarbeiten können und darf auf keinen Fall falsche Informationen einem
> User zur Verfügung stellen, der nicht zum Upload berechtigt ist.*
>
> *Baue auch ein simples CAPTCHA ein, um Bots zumindest ein wenig aufzuhalten. Bedenke,
> dass im Upload nur `.export`-Dateien hochgeladen werden dürfen und alles andere
> kategorisch abgelehnt wird. Bedenke auch, dass manche User versuchen werden,
> schadcode-bestückte Exports hochzuladen oder SQL-Injection im Passwortfeld zu probieren.*
>
> *Erstelle auch eine Danke-Seite mit der Nennung der Quellen, die zu diesem Tool geführt haben.
> Der Link zum dazugehörigen GitHub-Projekt ist:
> [https://github.com/lucatze/FritzBox-Backup-Decoder](https://github.com/lucatze/FritzBox-Backup-Decoder)*
>
> *Erstelle auch alle benötigten Dateien und Tags, damit Suchmaschinen die Seite gut
> indexieren können. Die Seite selbst soll komplett auf Englisch gehalten sein.*
>
> *Wenn du fertig mit den Basics der Seite bist, kannst du mit dem Einrichten des Servers
> weitermachen: `ssh administrator@fb-decoder.com -i ~/.ssh/[key]`*
>
> *Vergiss nicht, auch Let's Encrypt für die Domain einzurichten. Der VPS ist frisch
> aufgesetzt, Debian Trixie. Implementiere auch ein Rate-Limit, falls zu viele oder
> schädliche Anfragen kommen.*
>
> *Zeige den Nutzern auch, was sie erwarten können zu bekommen — als Beispiel sind in einem
> Arbeitsordner eine JSON- und eine TXT-Datei, die genau zeigen, wie der Output aussieht.
> Nutzer sollen Einblick haben, auch in Form eines Downloads.*

---

*Built with [Claude](https://claude.ai)*
