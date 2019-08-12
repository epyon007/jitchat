### Introdução

Rocket.Chat, é uma plataforma de chat Open-Source lançada no final de 2014. Após a aplicação estar pronta seu código não foi prontamente aberto. A abertura do código só aconteceu algum tempo depois, em maio de 2015, quando o idealizador do projeto observou um grande engajamento e disposição da comunidade no desenvolvimento de ferramentas Open-Source.

A ferramenta foi inicialmente concebida para atender uma necessidade de negócio levantada por um cliente do idealizador do projeto, o brasileiro Gabriel Engel. A ideia era criar uma plataforma de comunicação onde corretores de imóveis e clientes poderiam conversar a partir do site da empresa.

Ao longo dos últimos anos o Rocket.Chat vem ganhando muitos adeptos, por conta de sua praticidade e flexibilidade de customização.
Dentro dele, além de funcionalidades corriqueiras como criar grupos privados, realizar envio de mídias diversas (aúdio, vídeo, arquivos de texto, etc), podemos também integrá-lo a outras tecnologias.

Esta integração, pode ser desde configurar "Bots" para envio de respostas automáticas, informar status de execução de jobs do Rundeck, alertas de hosts do zabbix até a realização de videoconferências, por exemplo.

Neste post veremos uma aplicação prática de integração com uma ferramenta de videoconferência, o Jitsi.

O JITSI é uma plataforma Open-Source para realização de videoconferências. A operação desta ferramenta é bastante simples e intuitiva, os botões de funções (câmera, microfone, configurações, compartilhamento de tela, etc) são facilmente identificáveis.

Por ser uma solução Open-Source, não há limitação de licenças para que os utilizadores acessem as salas de conferência. Para realizar o acesso a estas videoconferências basta que os respectivos participantes possuam a URL correspondente à sala que querem acessar.

Vale lembrar que apesar de a quantidade de utilizadores não ter um limite estipulado, uma boa experiência no uso da ferramenta dependerá basicamente de como a infraestrutura dos utilizadores estará disposta (links de internet, conexão LAN, ou até mesmo a capacidade de hardware do servidor onde a aplicação está instalada).

Antes de começarmos, é importante notarmos os requisitos mínimos para a instalação do Rocket.Chat e do Jitsi em ambiente de produção. No caso do Rocket.Chat a configuração de hardware citada a seguir compreeende um ambiente de até 1000 usuários, com cerca de 300 acessos simultâneos e uso moderado de upload de mídias e integração com "bots". A capacidade pode variar de acordo com cada ambiente.

#### Requisitos - Rocket.Chat
   - Intel Xeon E5-2603 ou equivalente;
   - 4 GB RAM;
   - 500 GB ou mais de espaço em disco;
   - Ubuntu 18.04 LTS ou outras distribuições Linux.

No caso do Jitsi, os requisitos mínimos de instalação são baixos. No entanto, a necessidade de recursos de hardware pode variar de estrutura para estrutura.

#### Requisitos - Jitsi
   - 2 GHz CPU;
   - 1 GB RAM;
   - 25 GB ou mais de espaço em disco;
   - 10 Gb - Conexão Ethernet
   - Ubuntu 18.04 LTS ou outras distribuições Linux.


Hora de praticar. Utilizaremos neste passo a passo a distribuição Ubuntu Server 18.04.2 LTS, as aplicações que instalaremos podem ser utilizadas também em outros releases e distribuições, no entanto, podem ser necessários alguns ajustes.


### Instalação Rocket.Chat

#### Passo 1 - Preparar o servidor

Em nossa simulação utilizarei o padrão de configuração abaixo. Vale lembrar que neste caso estou simulando o ambiente em um laboratório por meio de máquinas virtuais, por isso as configurações são básicas.

- 2 GHz CPU
- 1 GB RAM
- 25 GB HDD
- Ubuntu Server 18.04.2 LTS
- SSH habilitado para o ROOT ou um usuario regular de SSH com privilegios de SUDO.

#### Passo 2 - Instalação de dependências

Vamos começar atualizando a lista de pacotes disponíveis no repositorio:

```shell
apt update
```

Após atualizar a lista de pacotes, adicionaremos a chave de criptografia do repositório para realizar a instalação do MongoDB.

```shell
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4

Executing: /tmp/apt-key-gpghome.60EJv83RoD/gpg.1.sh --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4
gpg: key 68818C72E52529D4: public key "MongoDB 4.0 Release Signing Key <packaging@mongodb.com>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Agora, adicionaremos o endereço do repositório nas listas do gerenciador de pacotes *apt*.

```shell
echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
```
Configuraremos o Node.js para ser instalado a partir do package manager.

```shell
apt update -y && apt install -y curl && curl -sL https://deb.nodesource.com/setup_8.x | sudo bash -
```

Em seguida, realizaremos a instalação dos pacotes *build-essential*, *mongodb-org*, *nodejs* e *graphicsmagick*.
```shell
apt install -y build-essential mongodb-org nodejs graphicsmagick
```

Utilizando o *npm*, instalaremos a versão do node.js necessária ao Rocket.Chat.

```shell
npm install -g inherits n && sudo n 8.11.4
```

#### Passo 3 - Baixar e instalar o Rocket.chat

Utilizaremos o comando abaixo para realizar o download da última versão do Rocket.Chat disponível.

```shell
curl -L https://releases.rocket.chat/latest/download -o /tmp/rocket.chat.tgz

% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                               Dload  Upload   Total   Spent    Left  Speed
100   223  100   223    0     0    219      0  0:00:01  0:00:01 --:--:--   219
100  135M  100  135M    0     0   418k      0  0:05:32  0:05:32 --:--:--  677k

```

A seguir, realizaremos a extração dos arquivos baixados dentro do diretório */tmp* .

```shell
tar -xzf /tmp/rocket.chat.tgz -C /tmp
```
Após realizarmos a extração dos arquivos, deveremos acessar o diretório a seguir para realizar a instalação.

```shell
cd /tmp/bundle/programs/server
```

Em seguida, utilizaremos o comando *npm* para realizar a instalação dos arquivos presentes no diretório.

```shell
npm install
```

Quando o comando anterior for concluído, utilizaremos o comando abaixo para mover os arquivos de instalação para o diretório */opt*.

```shell
mv /tmp/bundle /opt/Rocket.Chat
```

#### Passo 4 - Configurar o Rocket.Chat

Agora precisaremos configurar o Rocket.Chat, vamos começar pela criação de um usuário para o serviço, conforme abaixo:

```shell
useradd -M rocketchat && usermod -L rocketchat
```

Em seguida, alteraremos as permissões de usuário e grupo do diretório */opt/Rocket.Chat* para restringirmos o acesso ao diretório.

```shell
chown -R rocketchat:rocketchat /opt/Rocket.Chat
```

Uma vez definidas as permissões, deveremos criar um arquivo para inicialização do serviço do Rocket.Chat, definindo informações como URL e porta de acesso a aplicação, bem como informações relacionadas ao banco de dados MongoDB.

```shell
cat << EOF |sudo tee -a /lib/systemd/system/rocketchat.service
[Unit]
Description=The Rocket.Chat server
After=network.target remote-fs.target nss-lookup.target nginx.target mongod.target
[Service]
ExecStart=/usr/local/bin/node /opt/Rocket.Chat/main.js
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=rocketchat
User=rocketchat
Environment=MONGO_URL=mongodb://localhost:27017/rocketchat?replicaSet=rs01 MONGO_OPLOG_URL=mongodb://localhost:27017/local?replicaSet=rs01 ROOT_URL=http://localhost:3000/ PORT=3000
[Install]
WantedBy=multi-user.target
EOF
```

Para editarmos as informações que definimos no comando anterior, podemos acessar o arquivo *rocketchat.service* que criamos no diretório */lib/systemd/system/*, dentro deste arquivo podemos alterar variáveis de ambiente necessárias ao uso da aplicação (ex:ROOT_URL, MONGO_URL, MONGO_OPLOG_URL e PORT).

No exemplo abaixo, alterarei o endereço da ROOT_URL para *jitchat.4linux.com.br*. Notem que a alteração das variáveis MONGO_URL, MONGO_OPLOG_URL e PORT é opcional, dependendo de como estrutura do seu ambiente de TI está disposta você não precisará alterar nenhuma delas.

```
MONGO_URL=mongodb://localhost:27017/rocketchat?replicaSet=rs01
MONGO_OPLOG_URL=mongodb://localhost:27017/local?replicaSet=rs01
ROOT_URL=http://jitchat.4linux.com.br:3000
PORT=3000
```
Nos comandos a seguir, habilitaremos configurações necessárias ao funcionamento do MongoDB (parâmetros *engine* e *replicaset*, responsáveis sobre como serão administrados os dados armazenados no banco e também por redundância e alta disponibilidade do Banco de Dados).

```shell
sed -i "s/^#  engine:/  engine: mmapv1/"  /etc/mongod.conf
```

```shell
sed -i "s/^#replication:/replication:\n  replSetName: rs01/" /etc/mongod.conf
```

Habilitando e iniciando o serviço do MongoDB.
```shell
sudo systemctl enable mongod && sudo systemctl start mongod
```

```shell
mongo --eval "printjson(rs.initiate())"
```

Habilitando e iniciando o serviço do Rocket.Chat.
```shell
sudo systemctl enable rocketchat && sudo systemctl start rocketchat
```

### Instalação Jitsi
#### Passo 1 - Preparar o servidor

###### Máquina Virtual
Para a instalação do Jitsi utilizaremos em nosso laboratório o mesmo padrão de configuração utilizado na instalação do Rocket.Chat:
- 2 GHz CPU
- 1 GB RAM
- 25 GB HDD
- 10 Gb - Conexão Ethernet
- Ubuntu 18.04 LTS
- SSH habilitado para o ROOT ou um usuario regular de SSH com privilegios de SUDO.

###### Firewall
- Liberar portas 80 TCP (HTTP), 443 TCP (HTTPS) e 10000 - 20000 (UDP)

###### Checar regras de FIrewall

As *chains* devem estar sem configurações pré-definidas, sem quaisquer regras de firewall definidas.

```shell
iptables -L -n

Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

```
Podemos utilizar o **Uncomplicated Firewall**, instalado por padrão na distribuição Ubuntu.

```shell
ufw status

Status: inactive
```

Para o caso de o serviço de Firewall estar desabilitado, utilize o comando a seguir:
```shell
ufw enable

Command may disrupt existing ssh connections. Proceed with operation (y|n)? y
Firewall is active and enabled on system startup
```

Habilite a entrada de requisições SSH no firewall para possibilitar a administração remota do servidor:
```shell
ufw allow in ssh

Rule added
Rule added (v6)
```

Habilite também requisições às portas 80 e 443 para permitir o acesso pelos protocolos HTTP/HTTPS.
```shell
ufw allow in 80/tcp ; ufw allow in 443/tcp

Rule added
Rule added (v6)
Rule added
Rule added (v6)
```

A habilitação das portas UDP entre 10000 e 20000, só será realmente necessária caso sejam utilizados os serviços *Jigasi* (para integrar *Soft Phones* ao Jitsi) ou *Jitsi-Hammer* (programa utilizado para simular usuários acessando o Jitsi gerando tráfego RTP para esses usuários *falsos*).

Apesar de não utilizarmos estes recursos, vamos seguir a instalação padrão habilitando o acesso às portas.

```shell
ufw allow in 10000:20000/udp

Rule added
Rule added (v6)
```

Confirme as mudanças realizadas foram aplicadas após executar os comandos anteriores:
```shell
ufw status

Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
10000:20000/udp            ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
80/tcp (v6)                ALLOW       Anywhere (v6)
443/tcp (v6)               ALLOW       Anywhere (v6)
10000:20000/udp (v6)       ALLOW       Anywhere (v6)
```
A saída do comando *iptables* *-L* *-n* deverá ter um trecho semelhante ao exibido a seguir (ocultei parte da saída do comando pois ficou muito extensa e algumas informações não são necessárias para esta instalação).


```shell
iptables -L -n

Chain ufw-user-input (1 references)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443
ACCEPT     udp  --  0.0.0.0/0            0.0.0.0/0            multiport dports 10000:20000
```


###### O Firewall está pronto!


Agora, nós precisaremos pensar em um *DNS name* para atribuirmos ao servidor. Caso não exista um nome de dominio qualificado, podemos utilizar apenas o endereço IP, mas notem que a opção realizada aqui tem impacto nos próximos passos desta instalação.

Se definirmos um *DNS name*, não poderemos acessar as videoconferências a partir de um endereço IP, e vice-versa. Por isso, deveremos definir o endereço DNS a ser utilizado neste momento.

Eu utilizarei o nome "*jitchat.4linux.com.br*", mas vocês podem utilizar qualquer nome a sua escolha, dependendo da sua necessidade.


#### Passo 2 - Adicionar o repositório Jitsi

Para adicionar o repositório, em primeiro lugar, deveremos baixar a sua chave de criptografia com o comando abaixo:

```shell
wget https://download.jitsi.org/jitsi-key.gpg.key

--2019-08-10 19:08:25--  https://download.jitsi.org/jitsi-key.gpg.key
Resolving download.jitsi.org (download.jitsi.org)... 2001:660:2402::22, 130.79.200.22
Connecting to download.jitsi.org (download.jitsi.org)|2001:660:2402::22|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3071 (3.0K) [application/pgp-keys]
Saving to: ‘jitsi-key.gpg.key’

jitsi-key.gpg.key                     100%[=======================================================================>]   3.00K  --.-KB/s    in 0s

2019-08-10 19:08:27 (76.4 MB/s) - ‘jitsi-key.gpg.key’ saved [3071/3071]
```

 A seguir, devemos checar se a chave baixada é valida e não foi corrompida durante o download, este comando mostrará o ID da chave e o endereço de e-mail que está relacionado a ela.

```shell
gpg jitsi-key.gpg.key

gpg: WARNING: unsafe ownership on homedir '/home/suporte/.gnupg'
gpg: keybox '/home/suporte/.gnupg/pubring.kbx' created
gpg: WARNING: no command supplied.  Trying to guess what you mean ...
pub   rsa4096 2016-06-23 [SC]
      66A9CD0595D6AFA247290D3BEF8B479E2DC1389C
uid           Jitsi <dev@jitsi.org>
sub   rsa4096 2016-06-23 [E]
 ```

Após o comando abaixo, poderemos ver um ID que é identico ao exibido após executarmos o comando anterior. A partir dele, podemos escolher a opção correta a selecionar, escolhendo o número correspondente.

No meu caso a opção correta é a primeira, com *RSA key EF8B479E2DC1389C*.

Depois disso a chave é inserida no keyring do usuário local.

```shell
gpg --search-keys dev@jitsi.org

gpg: WARNING: unsafe ownership on homedir '/home/suporte/.gnupg'
gpg: data source: https://209.244.105.201:443
(1)	Jitsi <dev@jitsi.org>
	  4096 bit RSA key EF8B479E2DC1389C, created: 2016-06-23
(2)	Jitsi <dev@jitsi.org>
	  4096 bit RSA key E57E270828500F4D, created: 2016-06-21, expires: 2021-06-20
Keys 1-2 of 2 for "dev@jitsi.org".  Enter number(s), N)ext, or Q)uit > 1
gpg: key EF8B479E2DC1389C: 2 signatures not checked due to missing keys
gpg: /home/suporte/.gnupg/trustdb.gpg: trustdb created
gpg: key EF8B479E2DC1389C: public key "Jitsi <dev@jitsi.org>" imported
gpg: no ultimately trusted keys found
gpg: Total number processed: 1
gpg:               imported: 1

```

Agora, nós checaremos quem assinou esta chave e quem está atestando a validade dela.

Após o comando abaixo, veremos duas assinaturas que terão o status de **USER ID not found**, nós vamos importar estas chaves para ver os nomes dos assinantes e e-mails correspondentes, no comando a seguir.

```shell
gpg --list-sigs dev@jitsi.org

gpg: WARNING: unsafe ownership on homedir '/home/suporte/.gnupg'
pub   rsa4096 2016-06-23 [SC]
      66A9CD0595D6AFA247290D3BEF8B479E2DC1389C
uid           [ unknown] Jitsi <dev@jitsi.org>
sig 3        D6FF2D8D8030357F 2016-06-23  [User ID not found]
sig          3449EC3AC2EFE8AA 2017-02-06  [User ID not found]
sig 3        EF8B479E2DC1389C 2016-06-23  Jitsi <dev@jitsi.org>
sub   rsa4096 2016-06-23 [E]
sig          EF8B479E2DC1389C 2016-06-23  Jitsi <dev@jitsi.org>
```
No meu ambiente, os *ID's* não encontrados foram o **D6FF2D8D8030357F** e **3449EC3AC2EFE8AA**.

Sabendo os *ID's* que não foram encontrados, utilizaremos os próximos comandos para adicionar as informações faltantes utilizando estes *ID's*.

```shell
gpg --recv-keys D6FF2D8D8030357F

gpg: WARNING: unsafe ownership on homedir '/home/suporte/.gnupg'
gpg: key D6FF2D8D8030357F: 3 signatures not checked due to missing keys
gpg: key D6FF2D8D8030357F: public key "Damian Minkov <damencho@jitsi.org>" imported
gpg: no ultimately trusted keys found
gpg: Total number processed: 1
gpg:               imported: 1
```

```shell
gpg --recv-keys 3449EC3AC2EFE8AA

gpg: WARNING: unsafe ownership on homedir '/home/suporte/.gnupg'
gpg: key 3449EC3AC2EFE8AA: 15 signatures not checked due to missing keys
gpg: key 3449EC3AC2EFE8AA: public key "Ingo Bauersachs <ingo@jitsi.org>" imported
gpg: no ultimately trusted keys found
gpg: Total number processed: 1
gpg:               imported: 1
```

Esses passos foram realizados para nos certificarmos que os pacotes que estamos prestes a instalar realmente vem de uma fonte confiável, o próprio Jitsi. A partir disso poderemos adicionar a chave ao sistema.

```shell
apt-key add jitsi-key.gpg.key
```

Depois de adicionar a chave, devemos adicionar a entrada do endereço do repositorio Jitsi.

```shell
~# echo 'deb https://download.jitsi.org stable/' > /etc/apt/sources.list.d/jitsi-stable.list
```


#### Passo 3 - Certificado SSL

Para os certificados SSL podemos utilizar 3 opções:
- Utilizar um certificado já disponivel; (Substituir *dnsname* pelo nome DNS a ser informado durante a instalação do Jitsi, o certificado tem de ser valido para este dominio DNS)
    - /etc/ssl/dnsname.crt - Arquivo de certificado
    - /etc/ssl/dnsname.key - Arquivo de chave

- Certificado criado a partir do LetsEncrypt;

- Certificado auto-assinado (Neste caso será solicitada uma mudança para um certificado válido posteriormente).

Caso não possua um certificado, você terá a opção de criar um certificado válido durante a instalação.


#### Passo 4 - Instalar os pacotes

Agora realizaremos a instalação dos pacotes. Antes de iniciarmos o processo, precisamos atualizar a lista de pacotes disponiveis nos repositórios, a partir do comando abaixo:

```shell
apt update
```

Antes da instalação podemos definir qual WEBSERVER iremos utilizar (Apache, NGINX ou Jetty, por exemplo).

A instalação do Jitsi checa se há algum servidor WEB previamente instalado no servidor, primeiro checa se existe instalação do NGINX e em seguida se há instalação do APACHE. Caso não seja encontrado nenhum servidor WEB já instalado, por padrão o Jitsi realiza a configuração do Jetty.

Se escolhermos a instalação padrão do Jitsi(via Jetty), o serviço será provido na porta 443 (HTTPS), caso seja necessário um redirecionamento de HTTP para HTTPS, deveremos realizar a instalação do APACHE ou NGINX posteriormente.

Vamos utilizar a instalação padrão do Jitsi com o Jetty.

```shell
apt install jitsi-meet -y
```

Durante a instalação do pacote, nos depararemos com uma tela com o título **"Configuring jitsi-videobridge"**, nesta etapa informaremos o *DNS name* (ou endereço IP) que foi definido durante o "Passo 1".

![Configuring jitsi-videobridge](/assets/Configuring%20jitsi-videobridge.png)

No meu caso, utilizei o "*jitchat.4linux.com.br*" como definido inicialmente.

Após inserir o *DNS name* entraremos na tela com o título **"Configuring jitsi-meet-web-config"**, nesta tela serão expostas as opções relacionadas ao certificado SSL a ser utilizado na aplicação. Por ora, utilizaremos um certificado auto-assinado e posteriormente utilizaremos um certificado criado a partir do LetsEncrypt.

Após a conclusão da instalação, utilizaremos um script próprio do jitsi-meet para criar um certificado SSL a partir do LetsEncrypt.

A partir da execução do script, deveremos informar um endereço de e-mail para realizar a criação do certificado.

E-mail para informações sobre expiração de certificado: webmail@jitchat.4linux.com.br

```shell
/usr/share/jitsi-meet/scripts/install-letsencrypt-cert.sh

-------------------------------------------------------------------------
This script will:
- Need a working DNS record pointing to this machine(for domain jitchat.4linux.com.br)
- Download certbot-auto from https://dl.eff.org to /usr/local/sbin
- Install additional dependencies in order to request Let’s Encrypt certificate
- If running with jetty serving web content, will stop Jitsi Videobridge
- Configure and reload nginx or apache2, whichever is used

You need to agree to the ACME server's Subscriber Agreement (https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf)
by providing an email address for important account notifications
Enter your email and press [ENTER]: webmail@jitchat.4linux.com.br

--2019-08-10 19:58:12--  https://dl.eff.org/certbot-auto
Resolving dl.eff.org (dl.eff.org)... 2a04:4e42:16::201, 151.101.92.201
Connecting to dl.eff.org (dl.eff.org)|2a04:4e42:16::201|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 68689 (67K) [application/octet-stream]
Saving to: ‘certbot-auto’

certbot-auto                          100%[=======================================================================>]  67.08K   150KB/s    in 0.4s

2019-08-10 19:58:15 (150 KB/s) - ‘certbot-auto’ saved [68689/68689]

Bootstrapping dependencies for Debian-based OSes... (you can skip this with --no-bootstrap)
Hit:1 http://archive.ubuntu.com/ubuntu bionic InRelease
Hit:2 http://archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:3 http://archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:4 https://download.jitsi.org stable/ InRelease
Hit:5 http://archive.ubuntu.com/ubuntu bionic-security InRelease
Reading package lists... Done
Reading package lists... Done
Building dependency tree
Reading state information... Done
ca-certificates is already the newest version (20180409).
The following additional packages will be installed:
  binutils binutils-common binutils-x86-64-linux-gnu cpp cpp-7 gcc-7 gcc-7-base gcc-8-base libasan4 libatomic1 libbinutils libc-dev-bin libc6-dev
  libcc1-0 libcilkrts5 libexpat1 libexpat1-dev libgcc-7-dev libgcc1 libgomp1 libisl19 libitm1 liblsan0 libmpc3 libmpx2 libpython-dev
  libpython-stdlib libpython2.7 libpython2.7-dev libpython2.7-minimal libpython2.7-stdlib libquadmath0 libssl1.1 libstdc++6 libtsan0 libubsan0
  linux-libc-dev python-minimal python-pip-whl python-pkg-resources python2.7 python2.7-dev python2.7-minimal python3-distutils python3-lib2to3
  python3-virtualenv
Suggested packages:
  augeas-doc binutils-doc cpp-doc gcc-7-locales gcc-multilib make manpages-dev autoconf automake libtool flex bison gdb gcc-doc gcc-7-multilib
  gcc-7-doc libgcc1-dbg libgomp1-dbg libitm1-dbg libatomic1-dbg libasan4-dbg liblsan0-dbg libtsan0-dbg libubsan0-dbg libcilkrts5-dbg libmpx2-dbg
  libquadmath0-dbg augeas-tools glibc-doc libssl-doc python-doc python-tk python-setuptools python2.7-doc binfmt-support
Recommended packages:
  manpages-dev
The following NEW packages will be installed:
  augeas-lenses binutils binutils-common binutils-x86-64-linux-gnu cpp cpp-7 gcc gcc-7 gcc-7-base libasan4 libatomic1 libaugeas0 libbinutils
  libc-dev-bin libc6-dev libcc1-0 libcilkrts5 libexpat1-dev libffi-dev libgcc-7-dev libgomp1 libisl19 libitm1 liblsan0 libmpc3 libmpx2 libpython-dev
  libpython-stdlib libpython2.7 libpython2.7-dev libpython2.7-minimal libpython2.7-stdlib libquadmath0 libssl-dev libtsan0 libubsan0 linux-libc-dev
  python python-dev python-minimal python-pip-whl python-pkg-resources python-virtualenv python2.7 python2.7-dev python2.7-minimal python3-distutils
  python3-lib2to3 python3-virtualenv virtualenv
The following packages will be upgraded:
  gcc-8-base libexpat1 libgcc1 libssl1.1 libstdc++6 openssl
6 upgraded, 50 newly installed, 0 to remove and 148 not upgraded.
Need to get 65.1 MB of archives.
```

Após a conclusão do script, os serviços do Jitsi já estarão completamente operacionais.

Agora que temos as duas aplicações funcionando, poderemos acessá-las via browser e integrá-las podendo iniciar as videoconferências com o Jitsi a partir das conversas do Rocket.Chat.


### Integração Rocket.Chat

Vamos começar acessando a interface web para realizar as últimas configurações antes de iniciarmos a utilização do Rocket.Chat, para isso abra o seu browser e acesse a URL correspondente. No meu caso, utilizei https://rocket.4linux.com.br. Ao acessá-la pela primeira vez será exibido o *Setup Wizard* da aplicação, conforme imagem a seguir:

![Rocket.Chat - Setup Wizard 1](/assets/Rocket.Chat%20-%20Setup%20Wizard%201.png)

Após preenchermos os campos **Nome**, **Nome de usuário**, **E-mail** e **Senha** basta clicar em continuar.

![Rocket.Chat - Setup Wizard 1 - preenchido](/assets/Rocket.Chat%20-%20Setup%20Wizard%201%20-%20preenchido.png)

Após clicar em continuar, será exibida outra página solicitando mais informações, basta preenchê-las conforme sua necessidade e clicar em continuar.

![Rocket.Chat - Setup Wizard 2 - preenchido](/assets/Rocket.Chat%20-%20Setup%20Wizard%202%20-%20preenchido.png)

Ao preenchermos a segunda página, nos depararemos com mais uma página (esta será a penúltima). No campo **"Nome do Site"**, devemos colocar o título do site que queremos que seja exibido no browser, no campo **"Idioma"** pode ser mantido o padrão e no campo **"Tipo de servidor"** devemos selecionar a opção comunidade.

![Rocket.Chat - Setup Wizard 3 - preenchido](/assets/Rocket.Chat%20-%20Setup%20Wizard%203%20-%20preenchido.png)

Pronto, estamos na última página do *Setup Wizard*, basta selecionar a opção **"Mantenha-se autônomo, você precisará""** e clicar em continuar.

![Rocket.Chat - Setup Wizard 4 - preenchido](/assets/Rocket.Chat%20-%20Setup%20Wizard%204%20-%20preenchido.png)

Ao clicar na opção da última página seremos redirecionados para uma outra que nos informará que o ambiente está pronto, basta clicar no botão de confirmação e seremos redirecionados para a *Home* do Rocket.Chat.

No menu presente no lado esquerdo da página teremos um link de opções, ao clicarmos nele será exibido um outro link para a página de **Administração** da aplicação. Conforme imagem abaixo:


![Rocket.Chat - Home](/assets/Rocket.Chat%20-%20Home.png)
Quando acessarmos a página de Administração, deveremos ir até o final da lista de opções exibida à esquerda. Ao chegarmos no fim da barra de rolagem, veremos a opção **Vídeo Conferência**, clique nela.


![Rocket.Chat - Administracao](/assets/Rocket.Chat%20-%20Administracao.png)

Será exibida uma nova página com duas opções de tecnologias de vídeoconferências, **BigBlueButton** e **Jitsi**.

![Rocket.Chat - videoconf config](/assets/Rocket.Chat%20-%20videoconf%20config.png)


Ao clicarmos em **Jitsi**, chegaremos ao último passo da integração das ferramentas!

Nesta página serão exibidas as opções relacionadas ao Jitsi. Aqui, basta marcar as opções conforme a seguir:

- Ativado: Sim

- Domínio: nome_do_seu_site.com.br (apenas o domínio, não é necessario colocar “https://”)

- Prefixo da URL de Saída: **Rocketchat** está definido como padrão, mas você definir outro prefixo de acordo com a sua preferência.

- SSL: Sim

- Sempre abrir em nova janela: Sim

- Habilitar em Canais: Não

- Chrome Extension ID: Não é necessário alterar


![Rocket.Chat - videoconf config 2](/assets/Rocket.Chat%20-%20videoconf%20config%202.png)

Após definir estas configurações, basta salvar as alterações.
Pronto, o RocketChat está integrado ao Jitsi para realização de videoconferências!

Por fim, devemos testar se todas as configurações que definimos funcionaram corretamente. Para iniciar uma videoconferência com outro utilizador é necessário acessar a página de conversa do Rocket.Chat e clicar no primeiro ícone na parte superior direita da conversa, conforme imagem abaixo.

Ao clicar no ícone, será aberto um sub-menu com a opção Vídeo Chat, clique nele.

![Rocket.Chat - videoconf chat 1](/assets/Rocket.Chat%20-%20videoconf%20chat%201.png)

Será exibida uma janela menor perguntando se o usuário deseja iniciar uma videoconferência.

![Rocket.Chat - videoconf chat 2](/assets/Rocket.Chat%20-%20videoconf%20chat%202.png)

Caso a opção **Sim** seja escolhida, será aberta uma nova janela correspondente a sala de conferência. Aqui, o browser checará se o usuário deseja compartilhar dados a partir da câmera e microfone, clique em permitir para conseguir acessar os recursos.

![Rocket.Chat - videoconf chat 3](/assets/Rocket.Chat%20-%20videoconf%20chat%203.png)

Na imagem anterior podemos ver o Jitsi em funcionamento, caso os utilizadores queiram adicionar mais participantes à conferência, basta compartilhar a URL da sala.

Dentro da conferência, os utilizadores podem realizar ações como:
 - Compartilhar telas;
 - Compartilhar links do youtube;
 - Gravar a conferência;
 - Enviar mensagens de texto.

Depois da execução de todos estes passos, o ambiente está pronto para a utilização conjunta destas duas tecnologias.

Espero que tenham gostado, foi um prazer compartilhar este aprendizado com vocês.
