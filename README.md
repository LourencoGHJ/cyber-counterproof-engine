# Cyber Counterproof Engine (CCE)

**Protótipo defensivo para validar políticas de firewall e produzir evidência reproduzível.**

O CCE compara uma política declarativa com um conjunto de requisitos de segurança, executa testes determinísticos sobre o comportamento modelado e gera um relatório JSON com hashes SHA-256.

> **Estado:** MVP educativo. Os testes desta versão operam sobre um modelo de política em JSON. Não alteram `nftables`, não executam ataques contra sistemas e não provam que o firewall real está corretamente configurado. Essa integração será uma fase posterior, isolada e explicitamente autorizada.

## Funcionalidades

- Validação de formato e campos da política.
- Verificações de segurança: política de entrada permissiva, regras de entrada demasiado amplas e exposição de serviços.
- Testes de comportamento modelado para tráfego permitido/bloqueado.
- Relatório JSON com timestamp UTC, resultado, descobertas, testes e SHA-256 dos ficheiros de entrada.
- Testes unitários com `pytest`.
- Workflow GitHub Actions para executar testes em cada push e pull request.


## Licença

MIT — ver `LICENSE` (adicionar antes de publicar, caso queiras usar esta licença).
