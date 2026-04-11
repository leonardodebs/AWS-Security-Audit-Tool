# 🛡️ AWS Security Audit Tool - Documentação do Projeto

Este documento detalha o objetivo, a arquitetura e as etapas de implementação da ferramenta de auditoria de segurança automatizada desenvolvida para ambientes AWS.

---

## 🎯 1. Objetivo do Projeto

O objetivo principal deste projeto é estabelecer um sistema de **governança e monitoramento contínuo** para contas AWS, focando na detecção proativa de vulnerabilidades e configurações incorretas (misconfigurations).

A ferramenta foi projetada para atuar como uma sentinela automatizada, garantindo que as "boas práticas" da AWS (AWS Well-Architected Framework: Security Pillar) sejam aplicadas e mantidas ao longo do tempo.

### 🚩 Problemas Resolvidos:
- **Exposição de Dados:** Identificação de Buckets S3 abertos para a internet.
- **Privilégios Excessivos:** Detecção de usuários com permissões de Administrador desnecessárias.
- **Higiene de Credenciais:** Localização de chaves de acesso (Access Keys) antigas e não utilizadas.
- **Segurança de Rede:** Monitoramento de Grupos de Segurança (Firewalls) com portas críticas abertas para o mundo (0.0.0.0/0).
- **Detecção de Riscos em Tempo Real:** Identificação do uso de contas Root (que deve ser evitado para operações diárias).

---

## 🏗️ 2. Arquitetura e Tecnologias

O projeto utiliza uma stack moderna e modular para garantir escalabilidade e baixo custo:

- **Linguagem:** Python 3.12 (Motor do Scanner)
- **SDK AWS:** Boto3 (Interação profunda com APIs AWS)
- **Processamento:** ThreadPoolExecutor (Execução concorrente de múltiplos checks)
- **Infraestrutura:** Terraform (Infrastructure as Code - IaC)
- **Backend Nuvem:** AWS Lambda & EventBridge (Serverless e agendamento)
- **Relatórios:** JSON (Dados brutos) e HTML5 auto-contido (Visualização rápida)
- **Dashboard:** React + Vite + Tailwind CSS + Recharts (Interatividade e BI)

---

## 🛤️ 3. Etapas de Implementação

O projeto foi executado em quatro fases distintas, seguindo o ciclo de vida de desenvolvimento seguro:

### Fase 1: Fundação e Engenharia do Scanner
Desenvolvimento do motor principal em Python. Cada "check" de segurança foi implementado como um módulo independente, permitindo fácil expansão futura para novas regras.
- Implementação dos checks de S3, IAM, EC2 e CloudTrail.
- Sistema de tratamento de erros robusto para lidar com diferentes permissões e regiões.

### Fase 2: Visualização e Dashboard
Criação do ecossistema de relatórios.
- **HTML Reporter:** Geração de um arquivo único, com tema escuro e gráficos em JS, que pode ser aberto em qualquer navegador sem dependências.
- **React Dashboard:** Interface de Business Intelligence (BI) para carregar e comparar scans, facilitando a análise de tendências de segurança por especialistas.

### Fase 3: Remediação na Prática (Hardening)
Fase de aplicação real dos achados. O scanner identificou vulnerabilidades críticas no ambiente de teste, incluindo o uso da conta Root.
- Migração de permissões para um usuário IAM centralizado (`leonardo-admin`).
- Implementação de MFA (Multi-Factor Authentication).
- Revogação de chaves expostas e desativação de credenciais obsoletas.

### Fase 4: Automação em Nuvem (Próximo Passo)
Transposição do código local para um ambiente 100% AWS.
- Uso de Terraform para provisionar uma Lambda função e o agendamento diário.
- Configuração de alertas SNS (E-mail/SMS) para notificação imediata de novos incidentes.

---

## 📊 4. Impacto na Segurança

Ao final do projeto, a conta AWS passa por uma transformação de maturidade:

| Antes do Projeto | Depois do Projeto |
| :--- | :--- |
| Uso constante da Conta Root (Alto Risco) | Conta Root protegida por MFA e sem Access Keys |
| Chaves de acesso ativas sem monitoramento | Chaves não utilizadas são desativadas automaticamente |
| Visibilidade zero sobre Buckets públicos | Alertas imediatos sobre exposição de dados |
| Configuração manual via Console | Infraestrutura auditada por código |

---

## 👨‍💻 Desenvolvedor
*Documentação gerada como parte do projeto de Governança de Nuvem e Cloud Security.*
