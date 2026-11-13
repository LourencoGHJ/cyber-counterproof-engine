# CCE — Estado do projeto e roadmap

**Atualizado:** 13 de novembro de 2026  
**Branch principal:** `main`  
**PR #15:** integrado na `main` — merge commit `a6a1b22da8db7c6a117c8481c4f337d2c9a664d9`  
**PR #22:** documentação em revisão, apontada para `main`

Este documento distingue implementação, validação local, validação remota e trabalho futuro. A existência de um adaptador ou de testes simulados não equivale a validação operacional num host real.

## Estado de publicação

- A funcionalidade de comparação de interfaces exatas foi publicada no commit `d98996c0d728b40a7e2279e86cf83362d018bf3b`, validada e integrada através do PR #15.
- Os quatro workflows GitHub Actions associados a esse commit passaram: DevSecOps CI, CodeQL, Secret Scanning e Container Security.
- A Issue [#17 — interfaces exatas input/output](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/17) está concluída e fechada.
- A atualização documental está no PR [#22](https://github.com/LourencoGHJ/cyber-counterproof-engine/pull/22), que ainda precisa de integração.

## Estado por área

| Área | Estado | Evidência / limite |
|---|---|---|
| Núcleo CLI, validação de políticas e relatórios JSON | Implementado | Testes automatizados |
| Packet evaluator e cenários sintéticos | Implementado no subconjunto suportado | Resultados inconclusivos preservados |
| Parser IR e análise de conflitos iptables | Implementado no subconjunto suportado | Regras não interpretadas não são tratadas como seguras |
| Grafo estrutural de chains | Implementado | Alcance estrutural não prova correspondência de pacotes |
| Comparação semântica de políticas | Parcialmente implementada | Campos suportados e caminhos JUMP/GOTO conservadores |
| Interfaces exatas input/output | Implementadas e integradas | 295 testes locais; 4/4 workflows remotos aprovados |
| Linux Netfilter | Implementado e validado em Manjaro | Recolha read-only real |
| nftables nativo | Parcial | Políticas de base chains e inventário estrutural; sem cobertura semântica total |
| Windows Defender Firewall | Adaptador implementado | Testes simulados; validação real Windows 11 pendente |
| macOS PF/Application Firewall | Planeado | Sem adaptador |
| Dashboard HTTP/SSE | Implementado | Local por omissão, GET-only, recolha read-only; usa polling |
| DevSecOps | Workflows configurados e executados | CI, CodeQL, Gitleaks, Terraform/Checkov, Trivy |

## Validação local e remota

No Manjaro, para o código publicado no commit `d98996c0d728b40a7e2279e86cf83362d018bf3b`, em 13-11-2026:

- **295 testes aprovados**.
- Bandit: sem issues identificados; 12 Low, 0 Medium e 0 High.
- pip-audit: sem vulnerabilidades conhecidas nas dependências não editáveis verificadas; a distribuição CCE editável foi ignorada.
- pip check: sem dependências quebradas.
- `git diff --check`: sem erros.
- Recolha real read-only: 170 regras iptables, 69 chains, 88 totalmente interpretadas, 82 parcialmente interpretadas e 0 não interpretadas.
- Inventário nftables: 6 base chains e 0 divergências das políticas das base chains.
- 28 findings no total.

Os quatro workflows GitHub Actions associados ao commit publicado terminaram com sucesso: DevSecOps CI, CodeQL, Secret Scanning e Container Security.

### Resultado da recolha real

O estado global foi `INCONCLUSIVE`, com recolha parcial. Quatro comparações semânticas continuam inconclusivas porque alguns ramos individuais cobrem apenas parte do âmbito da política e o comparador ainda não agrega a união de vários ramos para provar cobertura total.

A análise nftables continua limitada às políticas das base chains e ao inventário estrutural suportado. Zero divergências de política das base chains não significa equivalência semântica de todas as regras nftables.

## Issues e prioridades

### Concluído

- [#17 — Suporte a interfaces exatas de entrada e saída](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/17) — implementado, testado, publicado, CI aprovada e integrado na `main`.

### P1 — Precisão semântica

- [#18 — Agregar ramos parciais JUMP/GOTO](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18).
- [#19 — Expandir a análise semântica nftables](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/19).

### P2 — Validação e expansão multiplataforma

- [#20 — Validar Windows Defender num Windows 11 real](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20).
- [#21 — Implementar adaptadores macOS PF/Application Firewall](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/21).

## Critérios de qualidade e conclusão

1. Não converter ausência de evidência em `PASS`.
2. Não ignorar seletores não modelados; manter `INCONCLUSIVE` quando não existe prova suficiente.
3. Manter as fontes iptables e nftables separadas.
4. Não expor regras reais ou valores sensíveis nos relatórios públicos.
5. Exigir testes unitários, de integração e validação de host antes de afirmar suporte operacional.
6. Associar os resultados de testes e segurança a commits SHA concretos.
7. Manter a recolha e o dashboard read-only, com privilégio mínimo.
8. Documentar explicitamente cobertura, limitações e critérios de suporte por plataforma.

O objetivo de conclusão do CCE é uma ferramenta defensiva, reproduzível e operacional para recolher evidência read-only, analisar políticas e regras dentro de um subconjunto formalmente suportado, explicar resultados, exportar relatórios e monitorizar alterações. Uma release não deve alegar cobertura integral de firewall enquanto persistirem construções semânticas não modeladas ou validação real em falta.

## Registo de publicação

- PR #15: integrado na `main`.
- Issue #17: fechada como concluída.
- PR #22: documentação a aguardar integração na `main`.
- Issues #18–#21: trabalho futuro aberto; não fazem parte das funcionalidades concluídas nesta baseline.
