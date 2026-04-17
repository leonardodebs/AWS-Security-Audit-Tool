# 🛡️ AWS Security Audit Tool

> **Auditoria de segurança automatizada para contas AWS** — detecta configurações incorretas, políticas IAM arriscadas, infraestrutura exposta e atividades suspeitas. Gera relatórios ricos em JSON e HTML. Implantável como uma Lambda agendada via Terraform.

![Architecture Platform](assets/architecture_professional.png)

---

## Índice

- [Funcionalidades](#funcionalidades)
- [Verificações de Segurança](#verificações-de-segurança)
- [Início Rápido](#início-rápido)
- [Executando Localmente](#executando-localmente)
- [Saída de Relatórios](#saída-de-relatórios)
- [Dashboard React](#dashboard-react)
- [Implantação com Terraform](#implantação-com-terraform)
- [Lambda e Agendamento](#lambda-e-agendamento)
- [Guia de Remediação](#guia-de-remediação)
- [Referência de Configuração](#referência-de-configuração)
- [Testes](#testes)
- [Estrutura do Repositório](#estrutura-do-repositório)

---

## Funcionalidades

| Funcionalidade | Detalhes |
|----------------|----------|
| **5 verificações de segurança** | S3, IAM (×2), EC2, CloudTrail |
| **Suporte a múltiplas regiões** | A verificação EC2 examina todas as regiões habilitadas |
| **Relatórios em dupla** | JSON (legível por máquina) + HTML (autocontido, tema escuro) |
| **Dashboard React** | Carregue relatórios JSON, filtre/pesquise em tempo real, gráficos |
| **Terraform IaC** | Lambda + EventBridge + S3 + SNS + CloudWatch |
| **Scans agendados** | Padrão: a cada 24 horas (configurável) |
| **Alertas via SNS** | Notificações por e-mail ao término do scan |
| **Códigos de saída para CI** | Saída não-zero quando há achados CRÍTICOS ou ALTOS |
| **Testes unitários** | Testes com mocks AWS via `moto` |

---

## Verificações de Segurança

### S3-001 · Buckets S3 com Acesso Público

**O que é verificado:**

- Configuração de Bloqueio de Acesso Público desabilitada no nível do bucket
- ACL concede `READ`/`WRITE` para `AllUsers` ou `AuthenticatedUsers`
- Política de bucket com `Principal: "*"` e `Effect: Allow`

**Severidade:** `CRÍTICA`

**Remediação:**

```bash
# Habilitar Bloqueio de Acesso Público (primeira etapa recomendada)
aws s3api put-public-access-block \
  --bucket <NOME_DO_BUCKET> \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Remover todas as concessões de ACL públicas
aws s3api put-bucket-acl --bucket <NOME_DO_BUCKET> --acl private

# Se precisar de hospedagem estática pública, use CloudFront + OAC
```

> **Boas práticas:** Habilite o Bloqueio de Acesso Público do S3 em nível de **conta** como salvaguarda:  
> `aws s3control put-public-access-block --account-id <ID_CONTA> --public-access-block-configuration BlockPublicAcls=true,...`

---

### IAM-001 · Usuários IAM com Privilégios de Administrador

**O que é verificado:**

- Política gerenciada `AdministratorAccess` anexada diretamente ao usuário
- Política inline com `Action: "*"` e `Effect: Allow`
- Associação a grupos que possuem políticas de administrador

**Severidade:** `CRÍTICA`

**Remediação:**

1. Identifique quais permissões o usuário realmente precisa.
2. Crie uma política IAM com escopo somente nessas permissões.
3. Desvincule o `AdministratorAccess` e anexe a política com escopo reduzido.
4. Prefira **IAM Roles** em vez de usuários IAM para acesso programático.
5. Habilite o **IAM Access Analyzer** para detectar automaticamente políticas muito permissivas.

```bash
# Desvincular AdministratorAccess de um usuário
aws iam detach-user-policy \
  --user-name <NOME_USUARIO> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

---

### IAM-002 · Chaves de Acesso Não Utilizadas

**O que é verificado:**

- Chaves de acesso ativas não utilizadas nos últimos **90 dias** (configurável)
- Chaves de acesso ativas que **nunca foram usadas** e são mais antigas que o limite definido

**Severidade:** `ALTA`

**Remediação:**

```bash
# Desativar (etapa mais segura como primeiro passo)
aws iam update-access-key \
  --user-name <NOME_USUARIO> \
  --access-key-id <ID_CHAVE> \
  --status Inactive

# Excluir após confirmar que nada foi afetado
aws iam delete-access-key \
  --user-name <NOME_USUARIO> \
  --access-key-id <ID_CHAVE>
```

> **Boas práticas:** Use **IAM Roles** com perfis de instância ou federação OIDC em vez de chaves de acesso de longa duração. Imponha a rotação de chaves com a regra AWS Config `access-keys-rotated`.

---

### EC2-001 · Grupos de Segurança Abertos para a Internet

**O que é verificado:**

- Regras de entrada que permitem tráfego de `0.0.0.0/0` ou `::/0`
- **CRÍTICO** para portas de alto risco: `22` (SSH), `3389` (RDP), `3306` (MySQL), `5432` (PostgreSQL), `27017` (MongoDB), `6379` (Redis), `9200` (Elasticsearch)
- **ALTO** para qualquer outra porta aberta para a internet

**Severidade:** `CRÍTICA` (portas de alto risco) / `ALTA` (demais)

**Remediação:**

```bash
# Revogar uma regra de entrada muito permissiva
aws ec2 revoke-security-group-ingress \
  --group-id <ID_SG> \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Substituir pelo seu IP real
aws ec2 authorize-security-group-ingress \
  --group-id <ID_SG> \
  --protocol tcp \
  --port 22 \
  --cidr <SEU_IP>/32
```

> **Boas práticas:**  
> - Use o **AWS Systems Manager Session Manager** para eliminar completamente a exposição SSH/RDP.  
> - Habilite o **VPC Flow Logs** para monitorar o tráfego.  
> - Aplique o **princípio do menor privilégio** nos grupos de segurança — prefira referenciar outros grupos de segurança em vez de intervalos CIDR.

---

### CT-001 · Uso da Conta Root

**O que é verificado:**

- Qualquer evento no CloudTrail nos últimos **90 dias** onde o principal é a conta root
- Cobre tanto logins no console quanto chamadas de API

**Severidade:** `CRÍTICA`

**Remediação:**

1. **Investigue imediatamente** o IP de origem e o evento no CloudTrail.
2. Habilite o **MFA** na conta root (se ainda não estiver habilitado).
3. Crie chaves de acesso root apenas quando estritamente necessário e exclua-as em seguida.
4. Configure um **alarme no CloudWatch** para ser alertado em tempo real:

```bash
# Criar um tópico SNS e alarme para uso root (via CloudFormation/Terraform)
# Consulte: https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-1
```

> **Boas práticas:** Trate a conta root como uma credencial de acesso emergencial. Armazene o dispositivo MFA com segurança (MFA de hardware é recomendado). Todas as operações rotineiras devem usar identidades IAM.

---

## Início Rápido

### Pré-requisitos

- Python 3.11+
- Credenciais AWS configuradas (`~/.aws/credentials`, variáveis de ambiente ou IAM role)
- Permissões: acesso de leitura ao S3, IAM, EC2, CloudTrail, STS

### Instalação

```bash
# Acesse o diretório do projeto
cd "AWS Security Audit Tool"

# Crie um ambiente virtual
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# Instale as dependências
pip install -r requirements.txt
pip install -e .              # instala o ponto de entrada CLI
```

### Configuração

```bash
# Copie o template de variáveis de ambiente
copy .env.example .env

# Edite o .env com suas credenciais/perfil AWS
```

---

## Executando Localmente

```bash
# Executar um scan completo (padrão: relatórios JSON + HTML em ./reports/)
python -m scanner.main

# Scan em uma região específica com perfil nomeado
python -m scanner.main --region sa-east-1 --profile meu-perfil

# Apenas JSON, com saída detalhada
python -m scanner.main --format json --log-level DEBUG

# Via entrada CLI instalada
aws-security-audit --output-dir ./meus-relatorios
```

**Códigos de saída:**

| Código | Significado |
|--------|-------------|
| `0` | Nenhum achado CRÍTICO ou ALTO |
| `1` | Achados CRÍTICOS ou ALTOS detectados |

---

## Saída de Relatórios

Os relatórios são salvos em `./reports/` (ou `--output-dir`):

```
reports/
├── aws_security_audit_123456789012_20240410T120000Z.json
└── aws_security_audit_123456789012_20240410T120000Z.html
```

### Estrutura do JSON

```json
{
  "account_id": "123456789012",
  "scan_time": "2024-04-10T12:00:00+00:00",
  "summary": {
    "total": 12,
    "failed": 10,
    "by_severity": { "CRITICAL": 3, "HIGH": 5, "MEDIUM": 2 },
    "by_check": { "S3-001": 2, "IAM-001": 1, "..." : "..." }
  },
  "findings": [
    {
      "check_id": "S3-001",
      "severity": "CRITICAL",
      "status": "FAILED",
      "resource_id": "arn:aws:s3:::meu-bucket",
      "description": "...",
      "recommendation": "...",
      "details": { "..." : "..." },
      "timestamp": "..."
    }
  ]
}
```

### Características do relatório HTML

- Cartões de resumo executivo e gráfico de distribuição por severidade
- Tabela completa de achados com pesquisa e filtro por severidade em tempo real
- Linhas de detalhe expansíveis com recomendações e dados brutos da API

---

## Dashboard React

O dashboard interativo carrega qualquer relatório JSON produzido pelo scanner.

```bash
cd dashboard
npm install
npm run dev          # Abre http://localhost:3000
```

**Funcionalidades:**

- Carregamento de relatório JSON via drag-and-drop
- Gráfico de barras (achados por verificação) + Gráfico de rosca (distribuição por severidade)
- Pesquisa em tempo real em todos os campos do achado
- Filtros por severidade e por ID de verificação
- Painel expansível de recomendação e detalhes técnicos por achado

---

## Implantação com Terraform

### O que o Terraform provisiona

| Recurso | Descrição |
|---------|-----------|
| `aws_lambda_function` | Função do scanner (Python 3.12, até 15 min de timeout) |
| `aws_iam_role` | Role de execução com privilégio mínimo |
| `aws_iam_policy` | Permissões de leitura de auditoria + escrita S3 para relatórios |
| `aws_s3_bucket` | Bucket de relatórios com criptografia, versionamento e ciclo de vida |
| `aws_cloudwatch_event_rule` | Agenda EventBridge (padrão: a cada 24 horas) |
| `aws_cloudwatch_log_group` | Retenção de log por 90 dias |
| `aws_cloudwatch_metric_alarm` | Alerta em caso de erros na Lambda |
| `aws_sns_topic` | Tópico de alertas (opcional) |
| `aws_sns_topic_subscription` | Assinatura por e-mail (opcional) |

### Implantar

```bash
cd terraform

# Inicializar os providers
terraform init

# Revisar o plano
terraform plan \
  -var="alert_email=voce@exemplo.com.br" \
  -var="aws_region=sa-east-1"

# Aplicar
terraform apply \
  -var="alert_email=voce@exemplo.com.br" \
  -var="aws_region=sa-east-1"
```

### Principais variáveis

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `aws_region` | `us-east-1` | Região de implantação |
| `project_name` | `aws-security-audit` | Prefixo dos nomes dos recursos |
| `scan_schedule_expression` | `rate(24 hours)` | Agenda do EventBridge |
| `unused_key_days` | `90` | Dias para sinalizar chave como inativa |
| `enable_sns_alerts` | `true` | Criar tópico SNS |
| `alert_email` | `""` | E-mail para assinatura SNS |
| `lambda_timeout_seconds` | `900` | Timeout da Lambda (máx. 900) |

### Exemplos de agendamento personalizado

```hcl
# A cada 6 horas
scan_schedule_expression = "rate(6 hours)"

# Toda semana útil às 08:00 UTC
scan_schedule_expression = "cron(0 8 ? * MON-FRI *)"
```

---

## Lambda e Agendamento

A função Lambda (`scanner/lambda_handler.py`) é disparada pela regra do EventBridge. Em cada invocação ela:

1. Executa todas as 5 verificações de segurança de forma concorrente
2. Grava os relatórios JSON + HTML em `/tmp/reports/`
3. Faz upload de ambos os relatórios para o S3 (`s3://<bucket>/reports/`)
4. Publica um resumo no tópico SNS (se configurado)
5. Retorna uma resposta JSON estruturada com o resumo

**Disparo manual:**

```bash
aws lambda invoke \
  --function-name aws-security-audit-scanner \
  --payload '{}' \
  response.json && cat response.json
```

**Visualizar logs:**

```bash
aws logs tail /aws/lambda/aws-security-audit-scanner --follow
```

---

## Referência de Configuração

| Variável de ambiente | Padrão | Descrição |
|----------------------|--------|-----------|
| `AWS_DEFAULT_REGION` | `us-east-1` | Região alvo |
| `AWS_PROFILE` | — | Perfil AWS nomeado |
| `AWS_ACCESS_KEY_ID` | — | Chave explícita (sobrescreve perfil) |
| `AWS_SECRET_ACCESS_KEY` | — | Secret explícito |
| `AWS_SESSION_TOKEN` | — | Token de sessão (para roles assumidas) |
| `OUTPUT_DIR` | `./reports` | Diretório local de relatórios |
| `UNUSED_KEY_DAYS` | `90` | Limite de dias para chaves inativas |
| `MAX_WORKERS` | `5` | Concorrência na execução das verificações |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `REPORT_S3_BUCKET` | — | Bucket S3 para upload dos relatórios |
| `SNS_TOPIC_ARN` | — | Tópico SNS para alertas |

---

## Testes

```bash
# Instalar dependências de desenvolvimento
pip install -r requirements-dev.txt

# Executar todos os testes
pytest

# Com relatório de cobertura
pytest --cov=scanner --cov=reporting --cov-report=term-missing

# Executar um arquivo de testes específico
pytest tests/test_s3_check.py -v
```

Os testes usam [moto](https://github.com/getmoto/moto) para simular serviços AWS localmente — **nenhuma conta AWS real é necessária**.

---

## Estrutura do Repositório

```
aws-security-audit/
├── scanner/                        # Pacote Python principal do scanner
│   ├── __init__.py
│   ├── config.py                   # Config central e constantes de severidade
│   ├── scanner.py                  # Orquestrador (executa todas as verificações)
│   ├── main.py                     # Ponto de entrada CLI
│   ├── lambda_handler.py           # Ponto de entrada AWS Lambda
│   ├── checks/
│   │   ├── base.py                 # BaseCheck + dataclass Finding
│   │   ├── s3_public_buckets.py    # S3-001
│   │   ├── iam_checks.py           # IAM-001, IAM-002
│   │   ├── ec2_security_groups.py  # EC2-001
│   │   └── cloudtrail_root_usage.py # CT-001
│   └── utils/
│       ├── aws_session.py          # Fábrica de sessão Boto3
│       └── logger.py               # Configuração de logging estruturado
│
├── reporting/                      # Geradores de relatório
│   ├── json_reporter.py            # Saída JSON + upload S3
│   └── html_reporter.py            # Relatório HTML autocontido
│
├── dashboard/                      # UI React
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       ├── App.jsx                 # Componente principal do dashboard
│       ├── App.module.css          # CSS com escopo
│       ├── index.css               # Sistema de design global
│       └── sampleData.js           # Dados demo para modo offline
│
├── terraform/                      # Infraestrutura como Código
│   ├── main.tf                     # Configuração do provider
│   ├── variables.tf                # Variáveis de entrada
│   ├── resources.tf                # Todos os recursos AWS
│   └── outputs.tf                  # Identificadores dos recursos
│
├── tests/                          # Testes unitários e de integração
│   ├── test_s3_check.py
│   └── test_iam_check.py
│
├── .env.example                    # Template de variáveis de ambiente
├── requirements.txt                # Dependências de produção
├── requirements-dev.txt            # Dependências de desenvolvimento/testes
├── pyproject.toml                  # Metadados do pacote + config pytest
└── README.md
```

---

## Observações de Segurança

- O scanner requer permissões IAM **somente de leitura**. A política do Terraform concede o mínimo necessário.
- Os relatórios podem conter nomes e IDs de recursos sensíveis — armazene o bucket S3 com criptografia **SSE-S3** e políticas de acesso restritas (ambas configuradas pelo Terraform).
- Nunca faça commit do arquivo `.env` ou de credenciais AWS no controle de versão.
- A role de execução da Lambda **não possui** permissões `iam:*` ou `s3:DeleteObject`.

---

## Licença

MIT — Consulte `LICENSE` para mais detalhes.
