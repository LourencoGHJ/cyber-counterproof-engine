# Cyber Counterproof Engine — Registo de Atualizações

**Última revisão:** 13 de novembro de 2026  
**Repositório:** [LourencoGHJ/cyber-counterproof-engine](https://github.com/LourencoGHJ/cyber-counterproof-engine)  
**Trabalho principal:** `feat/security-operations-dashboard`

Este documento regista capacidades implementadas, validações efetivamente executadas e limitações conhecidas. Distingue implementação, teste simulado e validação em host real.

## 1. Capacidades implementadas

### Núcleo de auditoria e evidência
- CLI Python para auditoria, validação de entradas, comparação de políticas, inspeção e análise.
- Validação de políticas e requisitos JSON antes da execução.
- Relatórios JSON, códigos de saída explícitos e hashes SHA-256 dos ficheiros de evidência.
- Monitorização periódica e deteção de desvios entre estados esperados e observados.

### Análise de firewall
- Validação de ficheiros nftables através de `nft --check`, sem aplicação de regras.
- Recolha read-only do estado ativo.
- Parser estrutural e representação intermédia (IR) de regras iptables.
- Comparação de regras com seletores suportados: chain, ação, protocolo, origem, porta de destino, estados de ligação e nomes exatos das interfaces de entrada/saída.
- Análise de conflitos: duplicados, redundância, shadowing demonstrável, potenciais sobreposições de veredictos e regras TCP impossíveis de corresponder.
- Grafo estrutural de chains com referências JUMP/GOTO, alvos não resolvidos e ciclos potenciais.
- Avaliação simplificada de pacotes e execução de cenários sintéticos, com resultado `INCONCLUSIVE` quando faltam semânticas necessárias.
- Percurso conservador de JUMP/GOTO/RETURN para caminhos suportados; a agregação de vários ramos parciais continua pendente.

### Adaptadores e recolha
- Deteção de plataforma e contrato comum para adaptadores.
- Linux Netfilter: `iptables-save`, `ip6tables-save` e leitura JSON nftables.
- Windows Defender Firewall: adaptador PowerShell/NetSecurity com leitura de `ActiveStore`; cobertura ainda validada por testes simulados, sem validação real em Windows 11.
- macOS PF e Application Firewall: planeados, ainda não implementados.
- Fontes iptables e nftables são reportadas separadamente para evitar dupla contagem da camada de compatibilidade iptables-nft.

### Dashboard em tempo real
- Dashboard HTTP local com API JSON e Server-Sent Events (SSE).
- Recolha read-only, polling configurável, heartbeat e publicação de eventos quando a evidência/análise muda.
- Bind local por omissão, autenticação para acesso remoto opt-in e endpoints GET-only.
- O servidor integrado não fornece TLS; acesso remoto deve ficar atrás de VPN ou reverse proxy HTTPS confiável.

### DevSecOps e distribuição
- GitHub Actions para testes, CodeQL, análise de segredos e segurança de contentores.
- Bandit e pip-audit para verificações locais.
- Terraform/Checkov e Trivy integrados nos workflows correspondentes.
- Docker com execução como utilizador não-root.
- Dependabot configurado para propostas de atualização.

## 2. Estado de suporte por plataforma

| Plataforma | Adaptador | Estado |
|---|---|---|
| Linux | Netfilter / iptables / nftables | Implementado e executado em recolha read-only real no Manjaro |
| Windows | Defender Firewall / NetSecurity | Implementado; testes simulados; validação real em Windows 11 pendente ([#20](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20)) |
| macOS | PF / Application Firewall | Planeado, não implementado ([#21](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/21)) |

## 3. Validação local registada em 13-11-2026

Os resultados seguintes foram recolhidos na árvore de trabalho local Manjaro/Python 3.14.7. À data deste registo, as alterações mais recentes ainda aguardavam publicação no branch remoto.

### Testes e qualidade
- Suite completa: **295 testes aprovados**.
- `git diff --check`: sem erros.
- Bandit: **No issues identified**; 12 findings Low, 0 Medium e 0 High.
- pip-audit: sem vulnerabilidades conhecidas nas dependências não editáveis verificadas; a distribuição CCE em modo editável foi explicitamente ignorada pelo auditor.
- pip check: sem requisitos quebrados.

Estes resultados comprovam apenas os caminhos e dependências efetivamente examinados; não constituem prova de ausência total de vulnerabilidades.

### Recolha read-only real no Manjaro
- Adaptador: `linux.netfilter`.
- Fontes: `iptables-save + nftables`.
- Regras iptables inventariadas: 170.
- Chains iptables: 69.
- Regras totalmente interpretadas pela IR: 88.
- Regras nftables inventariadas: 170.
- Base chains nftables: 6.
- Divergências de política das base chains nftables: 0.
- Findings totais: 28.
- Estado global: `INCONCLUSIVE`; recolha parcial: `true`.

A análise nftables continua limitada às políticas das base chains e ao inventário estrutural suportado. Zero divergências de política nas base chains não significa que todas as regras nftables sejam semanticamente equivalentes à política declarada.

### Comparações semânticas
Na última recolha foram observadas quatro comparações semânticas ainda `INCONCLUSIVE`:
- `allow-loopback` — IPv4.
- `allow-established` — IPv4 e IPv6.
- `allow-ssh-lab` — IPv4.

O bloqueio atual não é a interpretação de interfaces exatas. As comparações chegam ao percurso de chains, mas algumas regras cobrem apenas parte do âmbito da política. O comparador ainda não agrega a união de vários ramos parciais para provar cobertura total. Este trabalho está registado em [#18](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18).

## 4. Limitações conhecidas

1. **Agregação de ramos:** não agrega ainda múltiplos ramos parciais JUMP/GOTO para provar cobertura integral ([#18](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18)).
2. **nftables:** análise semântica nativa de regras ainda limitada; não existe alegação de cobertura integral ([#19](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/19)).
3. **Windows:** falta validar o adaptador num host Windows 11 real ([#20](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20)).
4. **macOS:** PF e Application Firewall ainda não têm adaptadores ([#21](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/21)).
5. **Kernel e tráfego:** a comparação estática e a avaliação simplificada não provam o comportamento real de todos os pacotes no kernel.
6. **Dashboard:** recolhe por polling; não é captura de eventos kernel/netlink e não garante latência end-to-end fixa.

## 5. Registo de Issues

- [#16 — Fundação de adaptadores multiplataforma](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/16) — concluído; histórico preservado.
- [#17 — Suporte a interfaces exatas na comparação de políticas](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/17) — implementação e validação local concluídas; publicação/CI pendentes.
- [#18 — Agregação de ramos parciais JUMP/GOTO](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18) — trabalho futuro.
- [#19 — Cobertura semântica nativa nftables](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/19) — trabalho futuro.
- [#20 — Validação real Windows 11](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20) — trabalho futuro.
- [#21 — Adaptadores macOS PF/Application Firewall](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/21) — trabalho futuro.

## 6. Política de segurança do desenvolvimento

- As recolhas descritas são read-only; nenhuma regra foi aplicada, removida ou modificada.
- Não transformar resultados desconhecidos em `PASS` ou `MATCHED`.
- Não publicar regras reais, IPs, portas, tokens ou relatórios sensíveis no Git.
- Executar validações reais apenas em sistemas próprios ou explicitamente autorizados.
- Manter limitações e níveis de validação documentados por plataforma.
