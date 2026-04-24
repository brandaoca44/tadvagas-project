# 💼 TADVagas - Backend

Plataforma focada em vagas **remotas e híbridas**, com ênfase em segurança, transparência e conexão eficiente entre candidatos e empresas.

Este repositório contém a API backend responsável por autenticação, controle de acesso, gerenciamento de usuários e base para o sistema de vagas.

---

## 🚀 Objetivo do Projeto

Criar um ambiente mais seguro e confiável para quem busca oportunidades, especialmente estágios e posições iniciais, reduzindo riscos como:

- Golpes disfarçados de vagas  
- Falta de transparência em processos seletivos  
- Informações inconsistentes ou enganosas  

---

## 🧠 Conceito

A plataforma é construída com foco em:

- Segurança como prioridade  
- Processos claros e confiáveis  
- Valorização de habilidades ao invés de aparência  
- Experiência mais direta e sem ruído  

---

## 🛠️ Tecnologias Utilizadas

### Backend
- Node.js
- NestJS
- TypeScript

### Banco de Dados
- PostgreSQL
- Prisma ORM

### Segurança
- JWT (Access + Refresh Tokens)
- Cookies HTTP-only
- Hash de senha com bcrypt
- Controle de acesso por roles

---

## 🔐 Funcionalidades Implementadas

- Registro de candidato  
- Registro de empresa  
- Login  
- Refresh token (sessão segura)  
- Logout  
- Rota protegida `/me`  
- Controle de autenticação com Guards e Strategies  
