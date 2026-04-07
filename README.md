Wireless Host Behavior Forensics
📁 Estrutura do Projeto

```text
whbf/
├── main.py              # Maestro do sistema e interface principal
├── protocols/           # Motores de ataque (ARP/DNS)
├── sniffer/             # Captura e tratamento de pacotes
├── utils/               # Funções auxiliares (IP, Root check, Scan)
├── logs/                # Armazenamento de evidências (.pcap)
└── requirements.txt     # Dependências do projeto

🛠️ Instalação
Pré-requisitos

    Linux 

    Python 3.10+

    Permissões de Root (necessário para manipulação de pacotes brutos)

passo a passo:

cd whbf
sudo pip3 install -r requirements.txt
sudo python3 main.py


Como Usar?

    Inicie o Modo Ativo: Insira o IP do Alvo, o IP do Roteador e o Domínio que deseja interceptar.

    Análise de Tráfego: O terminal exibirá em tempo real as conexões TCP/UDP e requisições DNS.

    Pós-Análise: Após encerrar a sessão (Ctrl+C), acesse a pasta logs/ para analisar o arquivo .pcap


sobre o projeto:

🔁 ARP (Address Resolution Protocol)

O ARP é responsável por descobrir qual endereço MAC está associado a um IP dentro da rede local.

⚠️ ARP Poisoning

O ARP Poisoning (ou ARP Spoofing) é uma técnica onde o atacante envia respostas ARP falsas na rede.

Com isso, ele faz os dispositivos acreditarem que:

ele é o roteador
ou que outro IP está associado ao MAC dele

Isso permite:

interceptar tráfego (Man-in-the-Middle)
monitorar comunicação entre dispositivos

🌍 DNS (Domain Name System)

O DNS é o sistema que traduz nomes de domínio em IP.

Exemplo:

google.com → 142.250.x.x

⚠️ DNS Spoofing

O DNS Spoofing consiste em responder consultas DNS com informações falsas.

Exemplo:

Usuário tenta acessar: facebook.com
Ferramenta responde com um IP controlado

📡 Sniffing (Captura de Pacotes)

Sniffing é o processo de capturar e analisar o tráfego de rede
Como tudo se conecta

No modo ativo, o WBHF combina essas técnicas:

ARP Poisoning → posiciona o atacante no meio da comunicação
DNS Spoofing → altera respostas de domínio
Sniffer → captura e analisa os dados

No modo passivo:

apenas o Sniffer é utilizado, sem interferência na rede.

autor:azrael
meu github:azrael-eternal
