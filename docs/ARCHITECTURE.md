# Arquitetura

## Fluxo

1. `models.py` lê JSON e rejeita entradas estruturalmente inválidas.
2. `engine.py` compara a política com requisitos declarativos e executa cenários de tráfego modelados.
3. `report.py` calcula SHA-256 dos ficheiros de entrada e gera um relatório JSON com data UTC.
4. `cli.py` coordena os módulos e devolve códigos de saída úteis para automação.
5. `tests/` verifica tanto o caso esperado como falhas intencionais.
6. `.github/workflows/ci.yml` executa os testes em push, pull request e execução manual.

## Decisões de desenho

- **Fail closed na validação:** entradas malformadas não são tratadas como políticas válidas.
- **Separação de responsabilidades:** leitura, motor de regras, relatórios e CLI estão separados.
- **Evidência reprodutível:** cada relatório regista hashes dos ficheiros de entrada.
- **Sem privilégios:** a versão inicial não precisa de `sudo` e não altera o sistema.
- **Limitações explícitas:** a avaliação é um modelo simples, não uma implementação do Netfilter.

## Evolução recomendada

A próxima integração deve primeiro invocar `nft --check` sobre um ficheiro de regras de laboratório, sem carregar regras no kernel. Depois pode comparar a política declarada com `nft list ruleset` em modo de leitura. Os testes de tráfego reais devem ocorrer numa VM isolada e descartável, com uma interface de rede de laboratório, nunca numa máquina ou rede sem autorização.
