### Tutorial: Resumo dos Passos do Vídeo

Este tutorial(https://www.youtube.com/watch?v=FbMpoVOorFI) descreve o processo de usar o `mutmut` para avaliar e melhorar a qualidade de uma suíte de testes em um projeto Python de exemplo.

#### 1. Preparação do Ambiente

1.  **Obter o Projeto**: O instrutor começa por baixar o projeto de exemplo a partir de um repositório no GitHub. Ele descompacta o ficheiro numa pasta local.
2.  **Configurar o Ambiente Virtual**: É utilizada uma ferramenta de ambiente virtual (`python3-venv`) para isolar as dependências do projeto. Um novo ambiente virtual é criado dentro da pasta do projeto.
3.  **Instalar as Dependências**: As bibliotecas necessárias para o projeto, que estão listadas no ficheiro `requirements.txt`, são instaladas no ambiente virtual. As três ferramentas principais são:
    * **pytest**: Para executar os testes de unidade.
    * **pytest-cov**: Para medir a cobertura de código dos testes.
    * **mutmut**: A ferramenta para o teste de mutação.

#### 2. Análise Inicial (Cobertura de Testes)

1.  **Executar os Testes Existentes**: O instrutor executa a suíte de testes com o `pytest` para garantir que todos os casos de teste estão a passar com o código original.
2.  **Gerar o Relatório de Cobertura**: Utilizando o `pytest-cov`, ele gera um relatório de cobertura em HTML para visualizar quais partes do código estão a ser exercitadas pelos testes.
3.  **Analisar a Cobertura**: A análise do relatório mostra que, embora as funções principais tenham 100% de cobertura de linha, isso não garante a qualidade dos testes. Ele questiona se a suíte de testes é suficiente para garantir que o programa foi bem testado.

#### 3. Execução do Teste de Mutação

1.  **Executar o `mutmut`**: O instrutor executa o comando `mutmut run`, apontando para o ficheiro de código-fonte a ser mutado (`cal.py`). A ferramenta cria centenas de "mutantes" (pequenas alterações no código) e executa os testes contra cada um deles.
2.  **Analisar o Relatório Inicial**: O resultado mostra que dos 233 mutantes criados, 126 foram "mortos" (detetados pelos testes) e 107 "sobreviveram". Isto indica que a suíte de testes, apesar da alta cobertura, tem pontos fracos.

#### 4. Análise e Melhoria Iterativa dos Testes

1.  **Listar Mutantes Sobreviventes**: O comando `mutmut results` é usado para listar todos os mutantes que sobreviveram.
2.  **Inspecionar um Mutante**: O instrutor escolhe um mutante específico (nº 27) e usa o comando `mutmut show 27` para ver a alteração exata que ele fez no código. A alteração foi trocar um `>` por um `>=` numa condição.
3.  **Criar um Novo Caso de Teste**: Com base na análise do mutante, ele cria um novo caso de teste projetado especificamente para "matar" aquele mutante. O novo teste exercita a condição exata que o mutante alterou, com valores que só passariam no código original.
4.  **Validar o Novo Teste**: Ele primeiro executa o `pytest` para garantir que o novo teste passa com o código original.
5.  **Re-executar o `mutmut`**: Por fim, ele executa o `mutmut run` novamente. O resultado mostra que a pontuação melhorou: agora 128 mutantes foram mortos e apenas 105 sobreviveram. A verificação do novo relatório HTML confirma que o mutante nº 27 foi eliminado.

O instrutor conclui explicando que este ciclo de **analisar um mutante sobrevivente e criar um teste para matá-lo** é a atividade central para usar o teste de mutação como um guia para fortalecer a qualidade e a robustez da suíte de testes.