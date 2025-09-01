### Tutorial: Teste de Mutação no Projeto `requests`

Este guia reproduz os passos para configurar um ambiente de desenvolvimento para a biblioteca `requests`, executar a suíte de testes, usar o `mutmut` para encontrar fraquezas e, finalmente, criar novos testes para "matar" os mutantes que sobreviveram.

#### Passo 1: Setup do Ambiente (Usando WSL no Windows)

O Teste de Mutação, especialmente com a ferramenta `mutmut`, funciona apenas em um ambiente Linux. O **WSL (Subsistema do Windows para Linux)** é a forma recomendada para utilizadores do Windows.

1.  **Instale o WSL**:
    Abra o PowerShell **como Administrador** e execute:

    ```bash
    wsl --install
    ```

    Isto irá instalar o WSL e o Ubuntu. Reinicie o seu computador se for solicitado.

2.  **Abra o Terminal Ubuntu**:
    No Menu Iniciar, procure e abra a aplicação "Ubuntu".

3.  **Instale as Ferramentas Essenciais**:
    Dentro do terminal Ubuntu, instale o Python, o gestor de pacotes `pip` e o `make`:

    ```bash
    sudo apt update
    sudo apt install python3-pip python3-venv make -y
    ```

4.  **Clone o Projeto e Navegue até à Pasta**:

    ```bash
    git clone https://github.com/psf/requests.git
    cd requests/
    ```

5.  **Crie e Ative um Ambiente Virtual**:

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

6.  **Instale as Dependências do Projeto**:
    Os comandos para instalação estão nos Makefile s

    ```bash
    python -m pip install -r requirements-dev.txt
    pip install pytest pytest-cov mutmut==3.3.1
    ```

#### Passo 2: Execução e Correção da Suíte de Testes Base

O Teste de Mutação só funciona se a suíte de testes original passar a 100%.

1.  **Gere os Certificados de Teste**:
    O projeto `requests` precisa de certificados para os seus testes. Use o `make` para criá-los:

    ```bash
    make -C ca clean
    ```

2.  **Execute o Pytest**:
    Corra a suíte de testes para garantir que tudo está a funcionar.

    ```bash
    pytest
    ```

3.  **Resultado Esperado**:
    Você deve ver uma saída indicando que todos os testes passaram (ex: `607 passed, 3 skipped, ...`). Se encontrar erros, reveja os passos anteriores, pois geralmente indicam um problema de configuração do ambiente.

#### Passo 3: Configuração e Execução do Teste de Mutação

Agora, vamos configurar e executar o `mutmut` para encontrar os pontos fracos.

1.  **Crie o Arquivo de Configuração**:
    Na raiz do projeto `requests`, altere um arquivo chamado `pyproject.toml` com o seguinte conteúdo. Este arquivo diz ao `mutmut` onde está o código-fonte e como executar os testes de forma otimizada, ignorando alguns testes que são incompatíveis com o `mutmut`.

    ```toml
    # pyproject.toml

    [tool.mutmut]
    # Aqui podemos cobrir o projeto por completo ou arquivos específicos (resultando em economia de recursos de processamento e trazendo respostas mais rápidas)
    paths_to_mutate = [ "src/requests/models.py" ]
    tests_dir = [ "tests/" ]


    # 2. Usar o comando de teste completo, com cobertura e exclusão de testes problemáticos
    test_command = "pytest --cov=requests tests/"
    ```

2.  **Execute o `mutmut`**:
    Este processo será demorado. O `mutmut` irá primeiro executar a suíte de testes completa para criar um mapa de cobertura (`mutmut-stats.json`) e depois começará a criar e a testar os mutantes.

    ```bash
    mutmut run
    ```
    ![Terminal exibindo resultados da primeira execução do mutmut, mostrando estatísticas como número de mutantes criados, mortos, sobreviventes e não testados. O ambiente é um terminal de linha de comando em modo texto, com saída informando progresso e status dos testes de mutação.](/mutantesInicial.png "Resultados da primeira execução")


#### Passo 4: Análise e Melhoria dos Testes

Após a conclusão da execução, é hora de analisar os resultados e fortalecer a suíte de testes.

1.  **Veja o Resumo dos Resultados**:
    Execute o seguinte comando para ver um resumo de quantos mutantes foram criados, mortos e quantos sobreviveram:

    ```bash
    mutmut results
    ```

    Foque-se na secção **SURVIVED**.

2.  **Analise um Mutante Sobrevivente**:
    Escolha um mutante da lista de sobreviventes. Por exemplo, `requests.models.xǁRequestǁprepare__mutmut_7`. Para ver a alteração exata que ele fez, use o comando `show`:

    ```bash
    mutmut show requests.models.xǁRequestǁprepare__mutmut_7
    ```

3.  **Escreva um Novo Teste para "Matar" o Mutante**:
    Com base na análise do `diff` do mutante, crie um novo caso de teste que falharia com o código mutado, mas passaria com o código original.

      * **Exemplo (para o mutante `...prepare__mutmut_7`)**: Este mutante anulava os dados `json`. O teste abaixo verifica se os dados `json` são corretamente processados. Adicione este teste ao arquivo `tests/test_requests.py`:

        ```python
        # No topo do arquivo, adicione a importação
        from requests.models import Request
        import json

        # Dentro da classe TestPreparingURLs
        def test_request_prepare_passes_json_data(self):
            json_data = {"key": "value"}
            req = Request(method="POST", url="http://example.com", json=json_data)
            p = req.prepare()
            assert p.body == json.dumps(json_data).encode("utf-8")
        ```

4.  **Repita o Ciclo**:
    Execute `mutmut run` novamente. O `mutmut` irá detetar que os testes mudaram e irá reavaliar os mutantes. O novo teste deverá agora "matar" o mutante que antes sobrevivia, melhorando a sua pontuação de mutação e, mais importante, a qualidade da sua suíte de testes. Repita os passos 2 e 3 para outros mutantes importantes.

    ![Terminal exibindo resultados da segunda execução do mutmut, mostrando estatísticas atualizadas como número de mutantes criados, mortos, sobreviventes e não testados. A saída indica progresso e melhoria na taxa de mutantes mortos após a adição de novos testes. ](/mutantesFinal.png "Resultados da segunda execução")