## Prérequis

Pour les workloads Windows utilisant WSL via Docker Desktop, configurez `vm.max_map_count` dans la distribution WSL de Docker Desktop. 

Commencez par ouvrir un shell dans cette distribution :
    wsl -d docker-desktop

Définissez ensuite la valeur :
    sysctl -w vm.max_map_count=262144
