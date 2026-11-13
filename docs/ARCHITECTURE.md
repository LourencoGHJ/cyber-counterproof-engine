# Arquitetura do Cyber Counterproof Engine

## 1. Visão geral

O CCE separa a validação de entradas, deteção da plataforma, recolha por adaptadores, parsing, análise semântica, evidência e apresentação. A recolha de firewall é read-only; não existe um caminho de execução que aplique ou remova regras.

## 2. Fluxo de dados

1. **Entradas e modelos — `models.py`**: lê e valida políticas, requisitos e cenários JSON. Campos inválidos são rejeitados antes da análise.
2. **Deteção de plataforma — `platform/detection.py`**: identifica sistema operativo, distribuição/versão, arquitetura, contexto de privilégios e ferramentas disponíveis.
3. **Contrato de adaptador — `adapters/`**: seleciona um adaptador por plataforma através de uma interface comum.
4. **Recolha — `collect` / adaptadores**: obtém snapshots e evidência através de operações fixas e read-only.
5. **Parsing e IR — `iptables_save.py`, `iptables_ir.py`**: valida a estrutura e converte as regras iptables suportadas numa representação intermédia com seletores normalizados.
6. **Análise — módulos de comparação, conflitos e fluxo**: compara campos declarativos, identifica potenciais conflitos e percorre referências de chains dentro do subconjunto suportado.
7. **Relatórios — `snapshot_analysis.py`, `report.py` e dashboard**: agrega estados, métricas, findings, limitações e hashes de evidência sem declarar conformidade integral quando a cobertura é insuficiente.

## 3. Adaptadores de plataforma

| Plataforma | Adaptador | Fonte | Estado |
|---|---|---|---|
| Linux | Netfilter | `iptables-save`, `ip6tables-save`, `nft -j list ruleset` | Implementado e validado por recolha real em Manjaro |
| Windows | Defender Firewall | PowerShell / `NetSecurity` / `ActiveStore` | Implementado; testes simulados, validação real pendente |
| macOS | PF / Application Firewall | A definir através de interfaces read-only suportadas | Planeado |

As fontes iptables e nftables são apresentadas separadamente. Em sistemas iptables-nft pode existir sobreposição entre a camada de compatibilidade e o ruleset nativo; somar os inventários como se fossem regras independentes seria incorreto.

## 4. Representação e comparação de regras

A IR iptables mantém, entre outros campos:
- Família, tabela, chain e linha de origem.
- Protocolo, origem/destino, interfaces de entrada/saída.
- Portas, estados de ligação e módulos.
- Target e operação JUMP/GOTO.
- Condições negadas, opções não suportadas e estado de interpretação.

A comparação declarativa suporta chain, ação, protocolo, rede de origem, porta de destino, estados de ligação e nomes exatos de interfaces. Interfaces wildcard, negadas ou não interpretadas permanecem inconclusivas.

## 5. Fluxo entre chains

O comparador segue caminhos JUMP/GOTO e os retornos suportados. Para um caminho, combina os seletores representáveis e só conclui quando a interseção demonstrada cobre o âmbito completo da política. Regras parcialmente interpretadas, recursão, negações, targets não resolvidos e condições desconhecidas não são silenciosamente ignorados.

A agregação da união de vários ramos parciais ainda não está implementada. Esse caso fica `INCONCLUSIVE` e é acompanhado em [Issue #18](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18).

O analisador de grafo estrutural é distinto do percurso semântico: identifica referências e alcançabilidade estrutural, mas não prova que os seletores de uma regra permitam a passagem de um pacote.

## 6. Dashboard HTTP/SSE

O dashboard recebe os resultados do coletor, disponibiliza endpoints GET e envia eventos SSE quando a evidência/análise muda. Ciclos sem alterações usam heartbeats leves. O serviço:
- Faz bind a `127.0.0.1` por omissão.
- Não altera a firewall.
- Pode usar autenticação quando o acesso remoto é explicitamente ativado.
- Não fornece TLS; o acesso remoto exige VPN ou reverse proxy HTTPS confiável.
- Deve correr como utilizador sem privilégios; a elevação read-only, quando necessária, limita-se aos comandos de listagem previstos.

## 7. Evidência, estados e segurança

- Cada snapshot/entrada relevante pode ser identificado por SHA-256; o hash não é assinatura digital.
- `MATCHED` é uma conclusão limitada aos campos e caminhos suportados, não uma prova global de conformidade.
- `INCONCLUSIVE` significa que a cobertura ou a semântica não permite uma conclusão segura.
- A recolha parcial, ferramentas ausentes e falhas de permissões ficam visíveis.
- Nenhuma regra real é aplicada, removida ou modificada.

## 8. Validação registada

Na validação local Manjaro do commit publicado `d98996c0d728b40a7e2279e86cf83362d018bf3b`, integrado na `main` pelo merge commit `a6a1b22da8db7c6a117c8481c4f337d2c9a664d9`, em 13-11-2026:
- 295 testes passaram.
- Bandit não identificou issues (0 Medium/High).
- pip-audit não encontrou vulnerabilidades nas dependências não editáveis verificadas; a distribuição CCE editável foi ignorada.
- Os quatro workflows GitHub Actions do commit publicado passaram (DevSecOps CI, CodeQL, Secret Scanning e Container Security).
- A recolha read-only real produziu estado global `INCONCLUSIVE`, com cobertura nftables limitada e quatro comparações semânticas ainda bloqueadas por ramos parciais.

Ver [README-ATUALIZACOES.md](../README-ATUALIZACOES.md) e [docs/ROADMAP.md](ROADMAP.md) para o registo e as próximas tarefas.
