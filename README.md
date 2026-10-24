
# Cyber Counterproof Engine (CCE)

**Python · Linux · nftables · Terraform · Checkov · GitHub Actions**

## Sobre o projeto

O **Cyber Counterproof Engine (CCE)** é um projeto de engenharia de segurança dedicado à validação de políticas defensivas, à análise de configurações e à produção de evidências técnicas.

Desenvolvido em Python, o projeto integra testes automatizados, análise de regras `nftables`, validação de políticas de segurança e geração de relatórios estruturados. O pipeline de integração contínua (CI), implementado com GitHub Actions, incorpora verificações de qualidade e segurança, incluindo análise estática com Bandit, auditoria de dependências com `pip-audit` e validação de Infraestrutura como Código (IaC) com Terraform e Checkov.

O objetivo do CCE é evoluir para um sistema capaz de identificar configurações incorretas, verificar a eficácia das correções em ambientes controlados e documentar os resultados de forma reproduzível.

## Objetivos

- Validar políticas e configurações de segurança defensiva.
- Automatizar testes e verificações de segurança.
- Analisar regras de firewall Linux através de `nftables`.
- Integrar verificações de segurança de IaC no pipeline de CI.
- Produzir relatórios estruturados que facilitem a análise dos resultados.
- Evoluir para a validação de medidas corretivas em ambientes isolados e controlados.

## Tecnologias

| Tecnologia | Finalidade |
|---|---|
| Python | Desenvolvimento do motor de validação e dos testes automatizados. |
| Linux | Ambiente de referência para os controlos de segurança do sistema. |
| nftables | Análise e validação de regras de firewall Linux. |
| Terraform | Definição e validação de configurações de infraestrutura como código. |
| Checkov | Análise estática de configurações IaC para identificar problemas de segurança. |
| GitHub Actions | Automatização do pipeline de integração contínua. |
| Bandit | Análise estática de segurança do código Python. |
| pip-audit | Identificação de vulnerabilidades conhecidas nas dependências Python. |
| pytest | Execução de testes automatizados. |
| JSON | Representação estruturada dos relatórios de validação. |

## Integração contínua e segurança

O projeto utiliza GitHub Actions para automatizar verificações durante o desenvolvimento. O pipeline inclui testes automatizados, verificações de segurança do código e das dependências, bem como validação Terraform e análise estática com Checkov.

Esta abordagem permite detetar problemas mais cedo no ciclo de desenvolvimento e criar uma base para integrar futuras verificações de segurança de forma sistemática.

## Evolução prevista

As próximas etapas de desenvolvimento incluem:

1. Reforçar os testes positivos e negativos para distinguir configurações seguras de configurações deliberadamente vulneráveis.
2. Integrar os resultados das ferramentas de análise nos relatórios do CCE.
3. Desenvolver um laboratório isolado para testar configurações e correções sem afetar sistemas reais.
4. Melhorar a rastreabilidade e a reprodução dos resultados.
5. Expandir a validação de controlos defensivos a outros cenários de infraestrutura e segurança cloud.

## Licença

A licença do projeto deverá ser indicada de acordo com o conteúdo do ficheiro `LICENSE` na raiz do repositório. Se for adotada a licença MIT, o ficheiro deverá conter os respetivos termos antes de o projeto ser apresentado como licenciado ao abrigo dessa licença.

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

