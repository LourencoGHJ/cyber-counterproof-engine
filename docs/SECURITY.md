# Modelo de segurança e limites

## Objetivo

Validar requisitos defensivos declarativos e detetar alguns erros comuns numa política de exemplo.

## Fora do âmbito desta versão

- Não aplica, remove ou modifica regras de firewall.
- Não lança scans de rede, exploração, força bruta ou ataques.
- Não garante que a política modelada coincide com o estado real do kernel.
- Não substitui auditoria, revisão humana, backups ou monitorização.
- Não assina criptograficamente os relatórios.

## Cuidados para desenvolvimento futuro

- Executar integrações em VM descartável e sem acesso a redes de produção.
- Usar permissões mínimas; evitar `sudo` na fase de análise.
- Validar e limitar todos os argumentos e ficheiros de entrada.
- Exigir aprovação humana antes de qualquer alteração real.
- Fazer backup e definir rollback antes de aplicar regras.
- Não expor dashboards de controlo diretamente à Internet.
- Não guardar segredos, tokens ou credenciais nos repositórios.
