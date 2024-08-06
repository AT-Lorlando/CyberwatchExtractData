# Cyberwatch Report Generator

## Présentation

Ce script Python est conçu pour extraire des données sous formes de CSV d'une instance Cyberwatch. Ces données peuvent ensuite être utilisées pour générer des rapports.

## Prérequis

- Python 3.x
- Accès à la base de données d'une instance Cyberwatch via un conteneur Docker et configuré en tant que master.
- PyMySQL, CVSS, PyTz

### Pourquoi et comment configurer Cyberwatch en tant que master

Ce script utilise une connexion directe à la base de données SQL de Cyberwatch. Cette base de données est à l'intérieur d'un conteneur Docker. Pour connecter le script, le port 3306 du conteneur doit être redirigé vers l'hôte. En configurant Cyberwatch en tant que master, cela modifie le Dockerfile de Cyberwatch pour rediriger notre port. Pour voir si Cyberwatch est configuré en tant que master, faites simplement un `docker ps | grep maria` et recherchez quelque chose comme **"3306->0.0.0.0:3306"**. Si vous obtenez seulement **"3306"**, alors votre Cyberwatch n'est pas correctement configuré. Pour configurer Cyberwatch en tant que master, faites `cyberwatch configure --master`. Si votre Cyberwatch est en mode hors ligne : `cyberwatch configure --offline --master`.

## Installation

### Prérequis

- Python 3.x
- pip (pour installer les dépendances)
- Peut nécessiter des privilèges d'administrateur pour installer et utiliser les dépendances.
- Avoir une instance Cyberwatch configurée en tant que master.

## Utilisation

### Commandes de base

Pour générer un rapport, utilisez la commande suivante :

```bash
python main.py
```

### Options

- `-h, --help` : Affiche l'aide.
- `-g, --group <group_ids>` : Identifiant(s) du groupe pour lequel générer le rapport.
- `-d, --days <days_number>` : Nombre de jours pour récupérer les données CVE, 0 pour tout le temps.
- `-i, --instance <ip>` : Adresse IP de l'instance Cyberwatch à utiliser.
- `-c, --config <path/to/config/file>` : Spécifie un fichier de configuration environnementale.
- `-l, --list` : Liste tous les groupes de l'instance, n'oubliez pas de spécifier l'adresse IP de l'instance.
- `-s, --split` : Génère un rapport séparé pour chaque serveur.

### Exemples

Pour générer un rapport CVE des 30 derniers jours pour un groupe de serveurs spécifique:

```bash
python main.py -g 6 -d 30 -i 172.0.0.1
```

Pour générer un rapport pour un groupe de serveurs spécifique, avec une configuration environnementale spécifique et en générant un rapport séparé pour chaque serveur:

```bash
python main.py -g 6 -i 172.0.0.1 -c ./environment/my_env.json -s
```

Pour générer un rapport pour plusieurs groupes de serveurs

```bash
python main.py -i 172.0.0.1 -g 1,2,3,4
```

## Configuration

1. **Connexion à la base de données** : Assurez-vous que votre script peut se connecter à la base de données de l'instance Cyberwatch. Les identifiants de la base de données doivent être correctement configurés dans le fichier `environement/.env`. Le fichier doit être structuré comme suit :

   ```env
    DB_USER=<username>
    DB_PASSWORD=<password>
    DB_NAME=<database_name>
   ```

2. **Bibliothèques externes** : Installez les bibliothèques Python nécessaires en exécutant :

   ```bash
   pip install <library_name>
   ```

3. **Données XML** : Le script analyse les fichiers XML CAPEC et CWE pour un contexte supplémentaire sur les vulnérabilités. Assurez-vous que ces fichiers sont mis à jour et situés dans le répertoire `assets`.
   Les fichiers peuvent être téléchargés à partir des liens suivants : [CAPEC](https://capec.mitre.org/data/downloads.html) et [CWE](https://cwe.mitre.org/data/downloads.html).

4. **CVSS environnemental** : Le script peut utiliser un fichier de configuration environnementale pour mapper les serveurs à leurs vecteurs CVSS environnementaux respectifs. Ce fichier doit être mis à jour avec les vecteurs environnementaux corrects pour chaque serveur. Le fichier doit être structuré comme suit :
   ```json
   {
     "DOMAINS": {
       "Stormshield": "Firewall",
       "Proxy": "DMZ",
       "WorkstationAdmin": "PRI",
       "WorkstationLinux": "PRI"
     },
     "ENVIRONMENTAL_VECTORS_V3": {
       "Firewall": "CR:M/IR:H/AR:H",
       "DMZ": "CR:L/IR:H/AR:H",
       "PRI": "CR:H/IR:H/AR:M"
     },
     "ENVIRONMENTAL_VECTORS_V2": {
       "Firewall": "CR:M/IR:H/AR:M",
       "DMZ": "CR:M/IR:H/AR:M",
       "PRI": "CR:H/IR:H/AR:H"
     },
     "SURFACES": {
       "Stormshield": "Network",
       "Proxy": "Adjacent",
       "WorkstationAdmin": "Local",
       "WorkstationLinux": "Local"
     },
     "SURFACES_VECTORS_MAX": {
       "Network": "/MAV:N",
       "Adjacent": "/MAV:A",
       "Local": "/MAV:L/MAC:H",
       "Physical": "/MAV:P/MAC:H"
     },
     "SURFACES_VECTORS_MIN": {
       "Network": "",
       "Adjacent": "",
       "Local": "",
       "Physical": ""
     },
     "SURFACES_VECTORS": {
       "Type A": {
         "MPR": {
           "L": "H"
         },
         "MS": {
           "U": "X",
           "C": "X"
         }
       }
     }
   }
   ```

La configuration est structurée comme suit :

- **DOMAINS** : Mappe chaque serveur ou actif à un type spécifique, permettant le regroupement basé sur des caractéristiques similaires ou des rôles au sein de l'organisation.
- **ENVIRONMENTAL_VECTORS** : Définit les vecteurs CVSS environnementaux pour chaque type de domaine, spécifiant comment les vulnérabilités impactent les actifs différemment en fonction de leur domaine.
- **SURFACES** : Mappe chaque serveur ou actif à une catégorie de surface, reflétant le niveau d'exposition ou le mode d'interaction de l'actif avec les attaquants potentiels.
- **SURFACES_VECTORS_MAX/MIN** : Spécifie les plafonds maximum et minimum pour les vecteurs CVSS en fonction de la catégorie de surface, permettant l'ajustement du score de vulnérabilité en fonction de l'exposition de l'actif.
- **SURFACES_VECTORS** : Traduction littérale si vous avez une configuration environnementale spécifique.

## Structure du projet

- `main.py` : Point d'entrée principal du script.
- `config.py` : Fonctions utilitaires pour charger et sauvegarder des fichiers de configuration JSON et parser les fichiers `.env`.
- `utils.py` : Fonctions utilitaires générales.
- `data.py` : Récupère les données CVE pour un groupe de serveurs.
- `database.py` : Fonctions pour interagir avec la base de données.
- `models.py` : Définit les modèles `Package`, `Update`, `Cve` et `Server`.
- `report_generator.py` : Génère les rapports CVE et CPE.
- `report_models.py` : Définit les différents types de rapports et les fonctions pour générer les lignes de rapport.
- `xml_parsers.py` : Parse les fichiers XML pour les données CAPEC et CWE.
- `logger.py` : Configuration du journal.
