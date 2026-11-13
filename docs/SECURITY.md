# Modelo de segurança e limites do CCE

## Objetivo

O Cyber Counterproof Engine (CCE) é uma ferramenta defensiva de validação, inspeção e análise de políticas de firewall. O objetivo é produzir evidência reproduzível e resultados conservadores, sem alterar a configuração do host analisado.

## Garantias operacionais do âmbito atual

- Os comandos de auditoria e comparação não aplicam, removem nem modificam regras de firewall.
- A recolha Linux usa operações de listagem read-only e argumentos de subprocesso fixos.
- A opção `--sudo-readonly`, quando necessária, eleva apenas os comandos de recolha explicitamente previstos; não deve ser usada como autorização para executar comandos arbitrários.
- A aplicação web deve correr como utilizador sem privilégios.
- O dashboard usa endpoints GET-only e Server-Sent Events para atualização da interface; não disponibiliza endpoints de alteração de firewall.
- O serviço faz bind a `127.0.0.1` por omissão.
- Acesso remoto é opt-in, exige token com pelo menos 32 caracteres e pressupõe transporte VPN ou HTTPS confiável.
- O servidor HTTP integrado não fornece TLS. Não expor a porta HTTP diretamente à Internet.
- A API não deve publicar texto bruto de regras nem valores de seletores de endereços/portas; os diagnósticos devem usar categorias normalizadas e seguras.

## Interpretação dos resultados

- `MATCHED` significa correspondência nos campos e caminhos explicitamente suportados; não prova conformidade global.
- `DRIFT` é reservado a divergências conclusivas dentro do âmbito analisado.
- `INCONCLUSIVE` é obrigatório quando faltam dados, existem seletores não modelados, a recolha é parcial ou a análise não consegue demonstrar a cobertura integral.
- `PASS` não deve ser usado como substituto de uma análise semântica completa do kernel.
- Hashes SHA-256 identificam evidência, mas não são assinaturas digitais e não garantem autenticidade do relatório.

## Limitações conhecidas

- A análise iptables cobre apenas o subconjunto implementado da tabela `filter` e dos hooks INPUT/OUTPUT/FORWARD.
- A agregação de múltiplos ramos parciais JUMP/GOTO está pendente ([#18](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18)).
- A análise nftables é limitada a políticas de base chains e inventário estrutural suportado ([#19](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/19)).
- O adaptador Windows existe, mas falta validação num host real Windows 11 ([#20](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20)).
- A avaliação de tráfego é um modelo simplificado, não uma implementação completa do Netfilter.

## Desenvolvimento e validação

- Executar integração de firewall em VM descartável e redes de laboratório.
- Usar permissões mínimas e manter a recolha read-only.
- Validar e limitar argumentos e ficheiros de entrada.
- Nunca incluir regras reais, endereços, portas, tokens ou credenciais em fixtures públicas.
- Fazer backup e definir rollback antes de qualquer tarefa futura que envolva alterações reais — essa tarefa requer autorização explícita, revisão humana e desenho separado.
- Revogar/rodar segredos encontrados antes de limpar histórico.
