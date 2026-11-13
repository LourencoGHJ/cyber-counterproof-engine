# CCE — Estado do projeto e roadmap

**Atualizado:** 13 de novembro de 2026  
**Branch de desenvolvimento:** `feat/security-operations-dashboard`  
**PR principal:** [#15 — Live read-only firewall dashboard with SSE](https://github.com/LourencoGHJ/cyber-counterproof-engine/pull/15)

Este roadmap separa trabalho implementado, validação efetuada e trabalho ainda em falta. A existência de um adaptador ou de testes simulados não equivale a validação em host real.

## Estado por área

| Área | Estado | Evidência / limite |
|---|---|---|
| Núcleo CLI, validação de políticas e relatórios JSON | Implementado | Testes automatizados |
| Packet evaluator e cenários sintéticos | Implementado no subconjunto suportado | Resultados inconclusivos preservados |
| Parser IR e análise de conflitos iptables | Implementado no subconjunto suportado | Regras não interpretadas não são tratadas como seguras |
| Grafo estrutural de chains | Implementado | Alcance estrutural não prova correspondência de pacotes |
| Comparação semântica de políticas | Implementada parcialmente | Campos suportados e caminhos JUMP/GOTO conservadores |
| Interfaces exatas input/output | Implementadas na árvore de trabalho local | 295 testes; publicação remota pendente à data deste registo |
| Linux Netfilter | Implementado e validado em Manjaro | Recolha read-only real |
| nftables nativo | Parcial | Políticas de base chains e inventário estrutural; sem cobertura semântica total |
| Windows Defender Firewall | Adaptador implementado | Testes simulados; Windows 11 real pendente |
| macOS PF/Application Firewall | Planeado | Sem adaptador |
| Dashboard HTTP/SSE | Implementado | Local por omissão, GET-only, recolha read-only |
| DevSecOps | Workflows configurados | CI, CodeQL, Gitleaks, Terraform/Checkov, Trivy, Dependabot |

## Última validação local conhecida

Na máquina Manjaro, árvore de trabalho local, em 13-11-2026:
- **295 testes aprovados**.
- Bandit: sem issues identificados; 0 Medium/High.
- pip-audit: sem vulnerabilidades conhecidas nas dependências não editáveis; a distribuição CCE editável foi ignorada.
- pip check: sem dependências quebradas.
- `git diff --check`: sem erros.
- Recolha real read-only: 170 regras iptables, 69 chains, 88 regras totalmente interpretadas, 6 base chains nftables, 0 divergências de políticas de base chain e 28 findings.
- Estado da recolha: `INCONCLUSIVE`, parcial. Quatro comparações semânticas continuam inconclusivas devido a cobertura de ramos parciais.

Estes resultados são locais e têm de ser associados ao commit publicado e à execução CI correspondente depois do push. Não representam o estado do SHA remoto anterior.

## Issues e prioridades

### P0 — Concluir e publicar a comparação com interfaces
- [#17 — Suporte a interfaces exatas de entrada e saída](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/17)
- Implementação e validação local concluídas; falta commit/push e CI no SHA publicado.

### P1 — Precisão semântica
- [#18 — Agregar ramos parciais JUMP/GOTO](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18)
- [#19 — Expandir semântica nftables](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/19)

### P2 — Validação multiplataforma
- [#20 — Validar Windows Defender num Windows 11 real](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20)
- [#21 — Implementar adaptadores macOS PF/Application Firewall](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/21)

## Critérios de qualidade do projeto

1. Não converter ausência de evidência em `PASS`.
2. Não ignorar seletores não modelados.
3. Manter as fontes iptables e nftables separadas.
4. Não expor regras reais ou valores sensíveis nos relatórios públicos.
5. Exigir testes unitários, integração e validação do host antes de afirmar suporte operacional.
6. Associar os resultados de segurança e testes a commits SHA concretos.
7. Manter o dashboard read-only e a execução com privilégio mínimo.

## Registo de publicação

À data desta revisão documental, a implementação mais recente de interfaces e os 295 testes passavam na árvore de trabalho local, mas ainda aguardavam publicação no branch remoto. Esta documentação é preparada num branch próprio e num PR em rascunho, para poder ser integrada depois da atualização do branch principal de desenvolvimento.
