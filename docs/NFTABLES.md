# Fase 2 — nftables

## Validar um ficheiro sem o aplicar

O ficheiro `examples/cce-test.nft` é uma configuração de laboratório.

```bash
python -m cce.cli validate-nft --file examples/cce-test.nft --output reports/nft-validation.json
```

A ferramenta chama `nft --check --file`; não executa `nft -f` nem aplica regras. Dependendo da distribuição e do contexto, a validação do kernel pode exigir privilégios. Não automatizamos `sudo`.

## Ler o ruleset ativo

```bash
python -m cce.cli inspect-live --output reports/live-summary.json
```

Para incluir o texto integral do ruleset (que pode revelar informação interna):

```bash
python -m cce.cli inspect-live --include-ruleset --output reports/live-ruleset.json
```

Se houver erro de permissões, consulta a mensagem e decide explicitamente se executas a leitura com privilégios. A ferramenta não altera o firewall.

## Limites

Validar sintaxe não prova que as regras são seguras. A consulta de leitura ainda não compara automaticamente toda a configuração ativa com os requisitos declarativos.
