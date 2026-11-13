# nftables — validação, recolha e âmbito de análise

## Validar um ficheiro sem aplicar regras

O ficheiro `examples/cce-test.nft` é uma configuração de laboratório.

```bash
cce validate-nft --file examples/cce-test.nft --output reports/nft-validation.json
```

A validação usa `nft --check --file`; não executa `nft -f` e não aplica a configuração. Dependendo da distribuição e do contexto, o kernel pode exigir privilégios para a verificação.

## Inspecionar o ruleset ativo

```bash
cce inspect-live --output reports/live-summary.json
```

Para incluir texto integral do ruleset — informação que pode revelar topologia, endereços, serviços e portas — usar explicitamente:

```bash
cce inspect-live --include-ruleset --output reports/live-ruleset.json
```

A inspeção é read-only. Em caso de permissões insuficientes, o erro é reportado; não são alteradas regras.

## Recolha combinada no Linux

O adaptador Linux pode recolher, através de comandos fixos:
- `iptables-save`;
- `ip6tables-save`;
- `nft -j list ruleset`.

Exemplo de recolha única:

```bash
cce collect --policy config/policy.json --once --source auto --timeout 10 --sudo-readonly --output reports/collection.json
```

A opção `--sudo-readonly` deve ser usada apenas quando as ferramentas de listagem requerem elevação e existe uma regra sudoers estritamente limitada aos comandos read-only previstos. O processo web não deve correr como root.

## Cobertura nftables efetivamente suportada

No estado atual, a análise nativa nftables:
- Compara políticas de base chains dentro do âmbito suportado.
- Recolhe inventário estrutural das tabelas, chains e regras suportadas.
- Reporta métricas, avisos e evidência separadamente da fonte iptables.
- Mantém `INCONCLUSIVE` quando a cobertura semântica é insuficiente.

**Não** afirma comparar semanticamente todas as expressões nftables nem provar a equivalência integral do ruleset. Conjuntos, maps, concatenations, verdict maps, expressões dinâmicas e outros constructs só podem ser considerados quando explicitamente suportados e testados.

Em sistemas iptables-nft, o inventário da camada de compatibilidade pode sobrepor-se às regras nativas. Por isso as contagens das duas fontes não devem ser somadas como se representassem necessariamente regras independentes.

## Próxima evolução

A expansão da comparação semântica nativa, com suporte incremental para expressões e preservação de resultados inconclusivos, é acompanhada em [Issue #19](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/19).

## Limites de segurança

- Validar sintaxe não prova que as regras são seguras.
- Um snapshot read-only não prova comportamento real de todos os pacotes no kernel.
- Não executar `nft -f`, `flush ruleset` ou outras operações de aplicação/remoção no âmbito de auditoria do CCE.
- Usar apenas snapshots de sistemas próprios ou autorizados.
