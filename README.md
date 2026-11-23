# skillcheck

Vérifie un skill d'agent IA (Claude Code, Codex, OpenClaw…) avant de lui faire confiance.
Analyse statique sans dépendance et hors ligne, puis l'avis d'un juge IA.
Il lit les fichiers et n'exécute jamais rien.

```
⛔ BLOQUÉ  notes-sync  · 1 fichier(s) lu(s)

Ce que ce skill peut faire
   Réseau      cdn.sync-helper.xyz, via urllib, webhook.site
   Secrets     .ssh/id_rsa, OPENAI_API_KEY
   Exécution   télécharge et exécute du code
   Persistance .zshrc

Juge IA (claude-opus-5-5) : ⛔ malveillant
   Le skill vole votre clé SSH et l'envoie à un service de collecte.

Pourquoi
   ⛔ Lit des identifiants de la machine et contacte Internet au même endroit
        SKILL.md:14   ssh_key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
```

## Utilisation

```bash
npm install -g .                       # depuis ce dossier
skillcheck ./mon-skill                 # analyse + juge IA
skillcheck ./mon-skill --no-judge      # analyse statique seule
skillcheck audit [--judge]             # tous les skills installés
skillcheck approve ./mon-skill         # approuve cette version (humain seulement)
```

Codes de sortie : `0` OK, `1` à vérifier, `2` bloqué. `--json` pour la CI.

## Le harness entier

```bash
skillcheck harness [--cwd projet] [--judge] [--full]
skillcheck harness approve
```

Il vérifie tout ce qui fait tourner Claude Code pour un projet :

| Pièce | Ce qui est vérifié |
|---|---|
| Hooks (réglages et plugins) | La commande **et** le script qu'elle lance ; un hook qui contacte Internet ; un hook `http` qui envoie chaque événement ailleurs |
| Serveurs MCP (`~/.claude.json`, `.mcp.json`, plugins, app de bureau) | Paquet `npx`/`uvx` sans version fixe ou en `@latest` ; serveur distant en `http://` ; Docker avec accès étendu ; secrets passés (noms seulement) |
| Réglages | `ANTHROPIC_BASE_URL` vers un proxy ; proxy réseau ; TLS désactivé ; télémétrie des prompts ; `apiKeyHelper` et `statusLine` ; `disableAllHooks` ; `enableAllProjectMcpServers` |
| Permissions | `bypassPermissions` ; accès à tout `~` ; règles allow qui permettent tout (`Bash(*)`, `Bash(curl:*)`, `Bash(python3:*)`…) |
| Consignes | `CLAUDE.md` (utilisateur, projet, dossiers parents), `AGENTS.md`, règles, **mémoire automatique** |
| Sous-agents et commandes slash | Injection ; `permissionMode: bypassPermissions` ; lignes `` !`commande` `` exécutées automatiquement |
| Plugins actifs et skills | Tout ce qui précède, plus l'analyse des skills |

Le résultat est une carte avec une ligne par pièce, et un résumé de ce que le harness fait **sans te demander** : hooks, MCP, réseau, secrets, règles allow risquées et trafic IA. Après `harness approve`, seules les pièces nouvelles ou modifiées et les nouvelles permissions sont signalées.

Les valeurs secrètes ne sont jamais affichées ni envoyées au juge : elles sont masquées (`<masqué>`). Le masquage couvre les variables par leur nom, mais aussi les secrets glissés dans une commande (`NOM_KEY=…`, `postgres://user:motdepasse@…`, `Bearer …`, jetons `sk-`, `re_`, `ghp_`, `AKIA`…). Un secret en clair dans les règles de permission ou dans `env` est lui-même signalé.

## Dans Claude Code

**Hooks.** `skillcheck hook --print-config` affiche le bloc à coller dans `~/.claude/settings.json` :
- **SessionStart** : au démarrage, Claude est prévenu si une pièce du harness est bloquée ou a changé depuis l'approbation (par exemple après la mise à jour automatique d'un plugin).
- **PreToolUse sur `Skill`** : avant que Claude utilise un skill, un skill bloqué est refusé et un skill « à vérifier » demande ton accord.
- **PostToolUse sur `Write|Edit|MultiEdit|Bash`** : quand Claude écrit un fichier de skill ou une config du harness (réglages, `.mcp.json`, `CLAUDE.md`, sous-agents…), ou lance une commande d'installation, il est prévenu en cas de problème.

**MCP.** Trois outils en lecture seule, `check_skill`, `check_harness` et `audit_skills` :
```bash
claude mcp add --transport stdio --scope user skillcheck -- node /chemin/vers/skillcheck/skillcheck.mjs mcp
```
L'approbation n'est pas exposée en MCP : un agent ne peut pas approuver un skill à ta place.

## Le juge IA

- Il passe par le SDK Anthropic (`npm install @anthropic-ai/sdk`) si `ANTHROPIC_API_KEY` est défini, sinon par le CLI `claude` (ton abonnement).
- Modèle : `claude-opus-5-5` par défaut, réglable avec `SKILLCHECK_MODEL`. `SKILLCHECK_JUDGE=off` le coupe.
- Il voit les fichiers du skill, encadrés par une balise aléatoire et marqués comme données non fiables, ainsi que les constats statiques.
- Chaque preuve doit **citer un passage exact**, vérifié ensuite par le code. Un « malveillant » sans preuve vérifiable redescend à « suspect ».
- Il peut **aggraver** un verdict, ou **lever un avertissement** preuve à l'appui. Il ne peut jamais lever un blocage statique, un fichier illisible ou une nouvelle permission.
- Le résultat est mis en cache par version du skill (`~/.skillcheck/judge-cache`). Une version que tu as approuvée à l'identique n'est pas rejugée.

## Les règles en bref

- **Permissions d'abord, pas de score** : réseau, secrets, exécution, persistance.
- **Ce qui bloque** :
  - télécharger puis exécuter (`curl | sh`, `sh -c "$(curl …)"`) ;
  - un reverse shell ;
  - l'écriture dans `.zshrc`, la crontab ou l'identité de l'agent ;
  - du texte Unicode invisible ;
  - un secret lu au même endroit qu'un appel réseau ;
  - une archive protégée par mot de passe ;
  - un site de copier-coller anonyme ;
  - des consignes téléchargées depuis Internet ;
  - un message de rançon.
- **Ce qui est seulement à vérifier** :
  - injection de prompt et consignes qui contournent l'utilisateur ;
  - commentaires cachés et code obfusqué ;
  - `eval` ;
  - services de collecte ;
  - jetons lus dans le navigateur ;
  - `curl | sh` depuis le site de l'éditeur du skill ou un installeur connu (Homebrew, rustup…).
- **Diff entre versions (rug-pull)** : après `approve`, seules les nouveautés sont signalées.

## Mesure

136 skills réels. Les 70 sains viennent d'anthropics/skills, openai/skills, obra/superpowers et vercel-labs/agent-skills. Les 66 malveillants viennent de [MalSkillBench](https://github.com/lxyeternal/MalSkillBench) : 56 trouvés dans la nature, 10 synthétiques. La liste est dans `bench/corpus-manifest.json`. Le corpus n'est pas inclus, car sa licence est réservée à la recherche académique.

Les règles ont été ajustées sur une moitié du corpus (`bench/tune-ids.json`). Les chiffres ci-dessous portent sur **l'autre moitié**, statique seule :

| | malveillants bloqués | malveillants signalés (⛔ ou ⚠️) | sains bloqués | sains signalés |
|---|---|---|---|---|
| statique v1 | 33 % | 42 % | 11,4 % | 14,3 % |
| statique v3 | 55 % | 67 % | 5,7 % | 14,3 % |
| statique v3 + juge (claude-opus-5-5) | 79 % | **97 %** | 5,7 % | **5,7 %** |

Les 2 skills sains bloqués le sont par la statique (`curl | sh` d'installeurs), que le juge n'a pas le droit de lever. Quand les filtres de sécurité du modèle refusent d'analyser un skill, il passe en « à vérifier » : sur ce corpus, les 3 refus concernaient tous des skills malveillants.

```bash
node bench/run.mjs <corpus> [--judge] --out res.tsv
python3 bench/split.py <dossier> res.tsv
```

## Limites

L'analyse statique ne voit pas une attaque écrite seulement en prose, ni une URL construite morceau par morceau. C'est le rôle du juge IA. Un ✅ veut dire « rien de suspect trouvé », pas « sûr ».

## Tests

```bash
npm test
```
