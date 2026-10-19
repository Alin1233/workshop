**SUJET DE WORKSHOP NATIONAL - BAC+5** 





**PROJECT RESILIENCE-ALPHA CYBER-RÉSILIENCE ET REPRISE AUTONOME** 



**Direction Pédagogique Nationale EPSI** 

Session Octobre 2026 • Apprenants en BAC+5 



<!-- Start of picture text -->
Ei epsi®<br><!-- End of picture text -->



<!-- Start of picture text -->
myDiL<br><!-- End of picture text -->

**SUJET DE WORKSHOP NATIONAL — BAC+5 PROJECT RESILIENCE-ALPHA • CYBER-RÉSILIENCE ET REPRISE AUTONOME** 

Apprenants en 5ème Année • Sprint d'ingénierie (4 jours) • Octobre 2026 

# **CINQ DOMAINES POUR UNE PLATEFORME UNIQUE** 

- **DÉVELOPPEMENT** · _Microservices, API, remédiation, interface React/Tailwind_ **INFRASTRUCTURE** · _Docker Compose, Ansible, Prometheus, Grafana, Loki_ **IA / DATA·** _Machine learning, agent RAG, Ollama et LangChain_ **CYBERSÉCURITÉ** · _WAF, SIEM, durcissement, Vault/SOPS_ **TRANSFORMATION** · _EBIOS RM, NIS2/DORA, PCA/PRA et arbitrages_ 

_Cinq piliers obligatoires, quelle que soit la composition du consortium._ 

# **VOTRE MISSION** 

_Vous avez quatre jours pour montrer qu’un système d’information critique peut encaisser un incident de sécurité et retrouver son fonctionnement sans qu’un opérateur intervienne pour le réparer. Pas sur le papier : sur un environnement que vous aurez conçu, développé, installé et testé vous-mêmes._ 

Le vendredi matin, votre consortium présentera une plateforme de paiement fictive, un incident de sécurité survenu sur cette plateforme, les mécanismes qui permettent d’identifier l’anomalie et la réponse engagée automatiquement pour rétablir le service. Vous devrez aussi expliquer vos décisions : ce que vous avez choisi de protéger, les compromis retenus, les limites de votre solution et ce que vous feriez différemment dans un contexte industriel. 

Ce workshop réunit les apprenants de dernière année des différentes formations EPSI — ECSI, EID, ECDPIA et EISI — ainsi que les expertises de transformation digitale représentées dans les groupes, notamment MSM. Les équipes sont pluridisciplinaires : la réussite du projet dépend autant de la qualité des développements que de leur intégration et des décisions prises en commun. 

# **1. CONTEXTE GLOBAL & ENJEUX** 

### **QUAND UN PAIEMENT NE PASSE PLUS** 

À l’automne 2026, une plateforme de paiement exploitée par une entreprise financière fictive subit une série d’incidents qui fragilisent la continuité de son activité. À plusieurs reprises, un service métier devient indisponible ou se comporte de manière anormale. Les équipes d’exploitation parviennent généralement à le remettre en route, mais leurs interventions restent manuelles, parfois longues et difficilement reproductibles. 

Ce fonctionnement n’est plus satisfaisant. Lorsqu’un service de paiement s’interrompt, les opérations des partenaires sont retardées, les utilisateurs perdent confiance et chaque minute d’indisponibilité complique le travail des équipes. À ces conséquences opérationnelles s’ajoutent des exigences de sécurité, de traçabilité et de résilience propres aux activités financières. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 2 sur 12 





La Direction Nationale de la Sûreté Numérique, organisme fictif chargé de piloter cette initiative, lance PROJECT RESILIENCE-ALPHA. Elle souhaite vérifier qu’une plateforme peut repérer un comportement anormal, analyser les signaux disponibles et engager seule une action corrective adaptée. L’objectif n’est pas de promettre un système infaillible. Il est de démontrer, sur un périmètre maîtrisé, qu’une reprise automatique peut être conçue, observée et vérifiée. 

Votre consortium intervient comme une équipe d’ingénierie indépendante. Vous concevez votre architecture et décidez de la façon d’utiliser les technologies demandées dans ce cahier des charges. L’environnement métier, les opérations et les données seront intégralement fictifs. Aucune donnée bancaire réelle ne doit être utilisée. 

# **2. LE RÉSULTAT ATTENDU** 

Le démonstrateur doit comporter un système de paiement simulé, hébergé dans une infrastructure conteneurisée. Une transaction fictive doit pouvoir être initiée et traitée par le système. Depuis un second ordinateur, votre équipe doit être capable de provoquer un incident de sécurité contrôlé, dans son seul environnement de travail. 

La suite doit se dérouler sans intervention corrective humaine : les événements sont collectés, le mécanisme de détection identifie l’anomalie, une décision de remédiation est prise, puis l’action correspondante est exécutée. L’équipe montre ensuite que le service métier est de nouveau utilisable, notamment par l’exécution réussie d’une nouvelle transaction fictive. 

Un conteneur qui redémarre ne constitue pas, à lui seul, une preuve de reprise. Si l’API reste inaccessible, si une opération métier échoue encore ou si des données sont incohérentes, le problème n’est pas résolu. Votre démonstration devra donc rendre visible l’état du service avant l’incident, pendant la perturbation et après la remédiation. 

L’incident principal est laissé à votre appréciation. Il doit être crédible dans le contexte retenu, reproductible, techniquement expliqué et compatible avec une réponse automatique dont vous pourrez démontrer l’efficacité. Vous pouvez aller plus loin en traitant plusieurs types de perturbations : indisponibilité contrôlée, défaillance applicative, corruption de données fictives, etc. Dans ce cas, veillez à ne pas confondre restauration de disponibilité et correction d’une compromission ou d’une fuite de données : les réponses attendues ne sont pas les mêmes. 

La solution finale doit réunir cinq domaines de travail complémentaires. Leur présence est obligatoire, même si aucun membre du groupe n’est issu de la spécialité correspondante. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 3 sur 1 2 





# **3. UNE ÉQUIPE, CINQ DOMAINES DE RESPONSABILITÉ** 

Les consortiums se constituent le lundi matin, en équipes de cinq apprenants. Les coachs peuvent autoriser un groupe de quatre ou six lorsque les effectifs du campus le nécessitent. Cherchez à réunir des profils différents, mais ne perdez pas de temps à construire une équipe « parfaite » : il n’est pas exigé d’avoir un représentant de chaque formation. 

Dès le lancement du projet, vous identifierez les personnes qui prennent en charge les différents domaines. Une même personne peut contribuer à plusieurs sujets ; inversement, un domaine peut mobiliser plusieurs membres. Ce qui compte, c’est que chacun assume une contribution clairement identifiable et que les décisions d’architecture restent partagées. 

Le workshop est organisé en quatre sprints, du lundi au jeudi. Le cadre et les attendus de chaque journée sont précisés en section 6. À l’intérieur de ce déroulement, vous restez responsables de la répartition des tâches, de la coordination, des arbitrages et de la conduite effective du projet. Les coachs accompagnent la démarche et valident les éléments prévus au cahier des charges, sans développer les solutions à votre place. 

### **3.1 — Développement : faire fonctionner le métier et la reprise** 

Vous devrez construire un SI de paiement fictif suffisamment complet pour illustrer un véritable processus métier : une interface, une API, l’exécution de transactions simulées, une gestion adaptée des accès et les données nécessaires au traitement. Le SI sera composé de microservices conteneurisés, notamment une base de données, une API métier, un service d’authentification et un frontal web. Leur intégration et leur comportement devront pouvoir être expliqués et démontrés. 

Le projet doit également disposer d’un moteur de remédiation. Il reçoit les informations utiles sur l’incident, engage les opérations prévues sur les services concernés et suit le retour à un état utilisable. Une interface de supervision permettra au jury d’observer les composants, les événements, les alertes et l’avancement de la reprise. 

Pour les services et les API REST ou gRPC, le choix s’effectue parmi les environnements prévus : Node.js, Python/FastAPI ou Go. Le tableau de bord est développé en React avec Tailwind CSS, conformément au pilier DEV de la proposition initiale. L’objectif reste une application cohérente, testée et compréhensible, dont les interfaces avec les autres composants sont maîtrisées. 

### **3.2 — Infrastructure : déployer, observer, rétablir** 

La plateforme doit pouvoir être déployée de manière reproductible sur le PC qui joue le rôle de serveur du consortium. Docker Compose est utilisé pour définir et orchestrer les conteneurs ; des playbooks Ansible assurent l’automatisation des opérations prévues au cahier des charges. Vous devez être capables d’expliquer la place de chacun de ces outils dans votre dispositif de déploiement et de reprise. 

Vous mettrez en place la stack d’observabilité prévue : Prometheus pour les métriques, Grafana pour la visualisation et Loki pour la centralisation des journaux. Cette chaîne doit renseigner sur l’état des services et alimenter réellement l’analyse de l’incident. L’utilisation d’Elastic Stack n’est pas attendue, compte tenu de la charge mémoire du PC Hôte. 

Le dépôt livré devra permettre de comprendre comment la plateforme est installée et relancée. Un assemblage qui ne fonctionne que sur la machine de son auteur, sans configuration documentée, ne répondrait pas pleinement à la demande. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 4 sur 12 





### **3.3 — Intelligence artificielle : identifier une anomalie et assister l’analyse** 

La détection d’anomalies ne devra pas se réduire à quelques conditions codées en dur. Vous concevrez un traitement de machine learning exploitant des métriques ou des journaux issus de l’environnement. À vous de choisir l’approche, de constituer les observations nécessaires et d’expliquer sur quelles bases le modèle distingue une situation ordinaire d’un comportement suspect. 

Le moteur de détection sera raccordé au dispositif de supervision et pourra alimenter la chaîne de remédiation. Le dossier technique devra permettre de comprendre les données utilisées, leur préparation, le modèle retenu, les résultats obtenus et les limites que vous avez constatées. 

Un second composant est attendu : un assistant local destiné aux opérateurs confrontés à l’incident. Il sera construit avec Ollama et LangChain, en associant un modèle de langage à une recherche documentaire de type RAG. L’assistant doit retrouver des informations utiles dans les procédures, les descriptions d’architecture ou les autres documents produits par l’équipe. Le modèle local n’excédera pas huit milliards de paramètres ; un modèle plus compact est recevable si son choix est cohérent avec le matériel et l’usage. 

L’assistant peut aider à comprendre ce qui se passe ou à consulter les procédures. Il ne doit pas être confondu avec l’automate chargé de la remédiation, ni disposer sans contrôle d’accès privilégiés au système. 

### **3.4 — Cybersécurité : éprouver la plateforme sans sortir du laboratoire** 

Vous devrez préparer au moins un scénario d’incident contrôlé déclenché depuis un ordinateur distinct du PC Hôte. Il ne s’agit pas d’une simulation graphique : l’action devra provoquer sur votre environnement un effet observable que vos mécanismes de surveillance pourront identifier. 

En parallèle, vous déploierez les dispositifs défensifs attendus : durcissement des composants et des accès, filtrage applicatif par WAF, suivi des événements dans un SIEM ou une fonction SOC intégrée à votre dispositif de supervision, et gestion des secrets avec HashiCorp Vault ou SOPS. Les journaux doivent rester exploitables pour l’investigation, et les privilèges accordés aux services doivent être maîtrisés. 

Portez une attention particulière au moteur de remédiation, qui peut disposer de droits élevés sur les conteneurs. Une plateforme conçue pour se défendre ne doit pas introduire, par facilité, une interface d’administration accessible à n’importe quel composant. 

Toutes les manipulations restent strictement limitées à votre SI fictif et aux machines autorisées de votre équipe. Les réseaux du campus, les autres groupes et les services tiers sont hors périmètre. 

### **3.5 — Gouvernance et transformation : justifier les choix** 

La résilience ne se limite pas aux opérations techniques. Votre commanditaire doit comprendre quels services vous jugez critiques, quels risques vous avez retenus et ce que coûte, pour l’activité, l’arrêt d’une fonction de paiement. Vous réaliserez une analyse structurée des risques en vous appuyant sur EBIOS Risk Manager, puis proposerez des objectifs de continuité et de reprise cohérents avec le démonstrateur. 

Vous produirez un PCA/PRA adapté à la solution livrée, en explicitant notamment les scénarios couverts, les responsabilités, les choix de restauration et les risques qui subsistent après la reprise. Vous analyserez également les enjeux NIS2 et DORA liés à une activité financière fictive, en distinguant les exigences pertinentes des obligations qui ne peuvent pas être démontrées par un prototype de quatre jours. 

Nous attendons ici une démarche de conseil et de pilotage : quels arbitrages feriez-vous, que recommanderiez-vous à une direction, et sur quels éléments vérifiables fonderiez-vous vos décisions ? Un rapport de conformité générique, sans lien avec votre architecture et vos essais, ne suffira pas. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 5 sur 1 2 



<!-- Start of picture text -->
Ey epsi®<br>informatique<br><!-- End of picture text -->



# **4. ENVIRONNEMENT MATÉRIEL ET RÉSEAU** 

Le PC Hôte est le poste qui exécute les services du démonstrateur. Il est distinct du second poste, utilisé pour déclencher les scénarios d’incident. Si les ressources sont insuffisantes pour exécuter le modèle de langage, un troisième ordinateur peut être réservé au calcul IA ; celui-ci n’hébergera alors que le modèle local et son interface d’accès. 



<!-- Start of picture text -->
PC HOTE (OBLIGATOIRE) SECOND PC PC DELESTAGE IA<br>(OBLIGATOIRE) (OPTIONNEL)<br>* Windows + Docker Desktop<br>(WSL2) + Autre PC du groupe | *Troisiéme PC du groupe, sila |<br>* Si cible, WAF, SIEM, Vault * Connecté uniquement au PA du ; RAM du PC Hote est :<br>* Prometheus / Grafana / Loki groupe ; insuffisante H<br>+ Moteur ML AlOps, orchestrateur, * Outils de déclenchement d'incident | + Héberge uniquement Ollama, H<br>dashboard * Aucun composant défensif ' exposé en API sur le PA du '<br>* Connecté au WiFi du campus : groupe :<br>+ PA du groupe (Point d'accés ; :<br>sans fil mobile) ; ;<br>PA du groupe RESILIENCE -G<n> (Point d'accés sans fil mobile Windows, réseau 192.168 .137.0/24) — réseau du<br>consortium<br><!-- End of picture text -->

**_Schéma d’implantation repris du sujet V4 : PC Hôte, second poste et délestage IA facultatif._** 

Pour le PC Hôte, la configuration retenue à ce stade reprend les prérequis de la proposition initiale : Windows 10 ou 11, droits d’administration, virtualisation activée, Docker Desktop avec WSL2, processeur de quatre cœurs au minimum, 16 Go de RAM et 50 Go libres sur SSD. Une machine de 32 Go de RAM, dotée d’un processeur de six à huit cœurs et de 100 Go libres, offrira davantage de marge. 

Pour le second poste, prévoyez un poste distinct disposant des outils nécessaires aux scénarios retenus. Une capacité de 8 Go de RAM peut servir de point de départ ; 16 Go offrent davantage de confort. Le PC de délestage IA, s’il est utilisé, est connecté au réseau local du groupe et expose uniquement les services requis. 

Le sujet impose d’utiliser le point d’accès sans fil mobile de Windows, par exemple sous le nom RESILIENCE-G<n>, avec une adresse de type 192.168.137.1 pour le PC Hôte. Les interfaces de la plateforme doivent être publiées avec discernement : base de données, secrets, interfaces de gestion et autres services internes ne sont pas destinés à être exposés au réseau pédagogique. 

En cas de difficulté matérielle, adressez-vous immédiatement au coach ; contourner une politique de sécurité n’est jamais une solution admise. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 6 sur 12 





# **5. LES OUTILS D’IA GÉNÉRATIVE FONT PARTIE DE VOTRE BOÎTE À OUTILS** 

Vous pouvez utiliser Claude, ChatGPT, Copilot et tout autre assistant pertinent pour élaborer votre architecture, produire du code, générer des configurations, préparer des jeux de tests, examiner des erreurs ou vous aider à formaliser votre documentation. Les bibliothèques, images et outils publics peuvent également être mobilisés. En revanche, aucun code de démarrage ni environnement applicatif construit spécialement pour ce workshop ne vous sera remis. 

Ces outils peuvent vous faire gagner beaucoup de temps. Ils peuvent aussi produire des composants incompatibles, des configurations fragiles ou des explications convaincantes mais incorrectes. Il vous appartient de vérifier ce que vous intégrez, de respecter les technologies prescrites, de conserver une maîtrise réelle du fonctionnement de votre solution et d’être en mesure de la défendre devant le jury. 

Ne communiquez pas aux services d’IA de clés ou secrets d’authentification, de données personnelles réelles, de documents confidentiels du campus ou de votre entreprise d’alternance. Vos responsabilités ne changent pas selon que le code a été écrit par vous ou généré par un outil. 

# **6. CHRONOLOGIE APPLIQUÉE DE LA SEMAINE (SPRINT)** 

Le sujet vous est remis le lundi matin. Le découpage ci-dessous reprend les étapes du sprint national et les obligations de la V4. 



## **LUNDI — Kick-off : architecture et EBIOS** 

Constitution des consortiums ; choix des postes et du réseau ; interfaces, architecture, matrice de risques et validation par les coachs. 



## **MARDI —  Production, IaC et modèles IA** 

Déploiement Docker Compose et Ansible ; microservices ; ML ; scénarios d’incident ; dossier de gouvernance NIS2/DORA. 



## **MERCREDI —  Intégration et premiers essais** 

Interconnexion WAF/SIEM, détection AIOps, remédiation et dashboard ; premiers tests de restauration 



## **JEUDI  —  Recette, chaos engineering et rendus** 

Injection de défaillances, tests, Clip Chrono, gel du code à 17 h et remise des fichiers avant 23h59 



## **VENDREDI — Jury local** 

Démonstration en direct, échanges avec le jury et sélection du consortium représentant le campus. 

Les résultats locaux sont annoncés à l’issue des passages. Les soutenances du vendredi matin ne doivent pas servir à poursuivre la production. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 7 sur 12 





# **7. RENDUS IMPÉRATIFS** 

Regroupez vos fichiers dans un dossier nommé **Workshop2026-M2-G<n>,** en **remplaçant <n> par le numéro de votre équipe** . Respectez les noms de fichiers ci-dessous : ils simplifient la collecte et la consultation des productions sur l’ensemble des campus. 

### **7.1.  Le dossier d’ingénierie et de gouvernance** 

**Workshop2026-M2-G<n>-Dossier.pdf —** Présentez les décisions qui structurent le projet : architecture et flux, rôle des différents composants, nature de l’incident, fonctionnement des mécanismes de détection et de reprise, résultats des essais, éléments de sécurité, analyse des risques, PCA/PRA et choix de gouvernance. Rendez également visible la contribution de chacun. 

Privilégiez un document précis et lisible plutôt qu’une accumulation de pages. Huit à douze pages, hors annexes, constituent un ordre de grandeur utile, non un quota. Les détails techniques volumineux peuvent rester dans le dépôt Git, à condition que le dossier y renvoie clairement. 

### **7.2. Un dossier technique et fonctionnel** 

**Workshop2026-M2-G<n>-Pres.pptx —** Préparez un support adapté à une présentation courte devant des professionnels. Il doit faciliter la compréhension de votre solution et de vos choix, sans se substituer à la démonstration. 

### **7.3. Le Clip Chrono** 

**Workshop2026-M2-G<n>-VidChrono.mp4 —** En soixante secondes maximum, montrez une séquence continue : déclenchement de l’incident depuis le second poste, apparition de l’anomalie, réaction du système et vérification du service rétabli. La capture doit être réalisée sans coupe permettant de masquer une action manuelle. Vous pouvez ajouter des titres ou des sous-titres pour rendre la démonstration compréhensible. 

### **7.4. L’archive des sources et du déploiement** 

**Workshop2026-M2-G<n>-Code.zip —** Remettez une archive structurée du dépôt Git avec les sources, configurations d’infrastructure, scripts d’incident et de ML, tests, documentation d’API et un README permettant de comprendre comment déployer et vérifier le système. Aucun secret ne doit être présent en clair dans l’archive. 

### **7.5. Le démonstrateur** 

Vous présenterez le système sur vos machines lors de la soutenance locale. Le jury doit pouvoir observer le fonctionnement réel de la plateforme, l’incident provoqué, sa prise en charge et les vérifications effectuées après la reprise. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 8 sur 12 

# **8. CADRE D’ÉVALUATION** 

Ce workshop permet à l’équipe pédagogique de situer les acquis de chacun en matière d’expertise, de conduite de projet, de collaboration et de résolution de problèmes. Une réalisation incomplète ne fait donc pas disparaître la qualité du travail individuel : les deux dimensions sont appréciées séparément. 

### **La note locale est calculée de la manière suivante :** 

**(note individuelle de suivi + 2 × note collective du jury) ÷ 3.** 

### **8.1. Suivi individuel — 20 points, coefficient 1** 

Les coachs observent les apprenants du lundi au jeudi selon cinq critères de quatre points chacun : leadership et posture professionnelle ; expertise dans le ou les domaines assumés ; capacité à résoudre les problèmes et à s’adapter ; coopération entre spécialités ; rigueur technique, traçabilité et documentation. La contribution effective de chaque personne compte davantage que l’intitulé de sa formation. 

### **8.2. Jury local — 20 points, coefficient 2** 

Les coachs observent les apprenants du lundi au jeudi selon cinq critères de quatre points chacun : leadership et posture professionnelle ; expertise dans le ou les domaines assumés ; capacité à résoudre les problèmes et à s’adapter ; coopération entre spécialités ; rigueur technique, traçabilité et documentation. La contribution effective de chaque personne compte davantage que l’intitulé de sa formation. 

### **Le jury local s’appuie sur la grille suivante :** 

|**Critère**|**Barème**|
|---|---|
|**Démonstration en direct et remédiation autonome**|5|
|**Expertise technique et cohérence des cinq domaines**|4|
|**Clip Chrono et dashboard**|4|
|**Gouvernance, NIS2/DORA et qualité du pitch**|4|
|**Dossier technique et réponses aux questions**|3|



Chaque équipe dispose de dix minutes : cinq minutes pour présenter et démontrer son travail, puis cinq minutes d’échange avec le jury. Les coachs évaluent par ailleurs le parcours individuel réalisé au cours de la semaine. 

La démonstration de reprise est un point décisif du sujet. Si le service ne se rétablit pas automatiquement et qu’une intervention corrective humaine devient nécessaire pendant le live, l’axe consacré à la remédiation reçoit 0 sur 5. Cette sanction porte sur le résultat technique présenté, pas sur l’ensemble du positionnement ni sur les efforts individuels observés. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 9 sur 12 





### **8.3. Finale nationale** 

Chaque campus désigne le consortium qui le représentera à la finale nationale, organisée environ trois semaines après les soutenances locales. Les dix équipes sélectionnées se retrouvent en direct sur Microsoft Teams. La démonstration est diffusée depuis le PC Hôte. 

Le temps de passage est limité à cinq minutes : une première minute pour présenter la démarche, avec une introduction individuelle en anglais ; une deuxième minute pour diffuser le Clip Chrono ; puis trois minutes pour montrer, en direct, l’incident et la reprise automatique. Une démonstration en fonctionnement vaut davantage qu’une suite de diapositives. 

### **La notation technique nationale reste établie sur 70 points :** 



<!-- Start of picture text -->
Axe d’évaluation national Points Indicateurs recherchés<br>  Pitch stratégique    10<br>  Clip Chrono   15<br>  Démonstration en direct   25<br>  Expertise technique et architecture   10<br>  Gouvernance et conformité   10<br>  TOTAL   70<br><!-- End of picture text -->

### **8.4. Le Scrutin National Croisé (Distribution du Capital de 43 points** 

L'évaluation finale est opérée par un collège de **2 jurys locaux par Campus** (soit 20 jurys nationaux au total). À l'issue des passages des 10 campus, chaque jury compile ses grilles techniques pour établir son classement final de la 1ère à la 10ème place. Ce classement dicte la distribution **mécanique et obligatoire de son capital de 43 points** de vote selon la grille stricte suivante : 

|**AXE D'ÉVALUATION NATIONAL**|**POINTS**|
|---|---|
|**1er du classement**|12 points|
|**2ème du classement**|10 points|
|**3ème du classement**|8 points|
|**4ème du classement**|6 points|
|**5ème du classement**|4 points|
|**6ème du classement**|2 points|
|**7ème du classement**|1 points|
|**8e, 9e et 10e places**|0 points|



EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 10 sur 12 





# **9. CONDITIONS DE TRAVAIL ET SÉCURITÉ** 

Vous émargerez sur Edusign dans les quinze premières minutes de chaque demi-journée. Les espaces affectés à votre groupe restent votre lieu de travail principal ; tout accès aux installations particulières du campus doit respecter les consignes des coachs. Les salles et les équipements doivent être rendus propres et en bon état. Votre présence est attendue pendant l’ensemble des soutenances locales et lors de la retransmission de la finale nationale. 

Aucune activité ne doit concerner les réseaux du campus, un autre consortium, un équipement tiers ou un service accessible sur Internet. Ne faites circuler aucune donnée financière authentique. Toute expérimentation susceptible de sortir du périmètre autorisé doit être interrompue et signalée au coach. La liberté technique du workshop s’exerce à l’intérieur de ces limites. 

# **DERNIER POINT : CE QUE LE JURY CHERCHERA À COMPRENDRE** 

Il ne vous est pas demandé de fabriquer en quatre jours une plateforme de paiement industrielle prête à être mise en production. **Vous devez en revanche démontrer une chaîne de cyber-résilience crédible, en vous appuyant sur les composants et technologies prescrits, suffisamment aboutie pour être exécutée et discutée techniquement.** 

Vous serez jugés sur ce que vous avez réellement construit, sur les preuves de fonctionnement présentées et sur votre capacité à expliquer les décisions prises sous contrainte de temps. 

Dans le cadre des sprints et des technologies demandés, vos choix d’architecture et votre manière de conduire le projet feront toute la différence. À vous de montrer que l’ensemble tient en conditions réelles de démonstration. 

EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 11 sur 1 2 





# **QUELQUES TERMES UTILES** 

Les sigles les plus utilisés dans le sujet sont rappelés ci-dessous. 

|**AIOps**|**RAG**|
|---|---|
|IA appliquée à l’analyse et à l’automatisation des|Recherche documentaire enrichissant un|
|**ML**|**IaC**|
|Machine learning: apprentissage automatique.|Infrastructure as Code : infrastructure décrite|
|**Blue Team**|**WAF**|
|Activités défensives de détection et de réponse.|Pare-feu applicatif.|
|**SIEM**|**EBIOS RM**|
|Collecte et corrélation des événements de|Méthode d’appréciation des risques cyber.|
|**NIS2**|**DORA**|
|Directive européenne relative à la sécurité des|Règlement européen sur la résilience|
|**PCA / PRA**|**Zero-Touch Recovery**|
|Plans de continuité et de reprise d’activité.|Reprise automatisée sans intervention|



EPSI — Direction Pédagogique Nationale — Workshop Bac+5 2026-27 

Page 1 2 sur 1 2 

