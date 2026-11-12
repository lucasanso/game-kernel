# Testes

Todos os testes são controlados por **pytest**. O código C++ é testado pelo módulo `gk_native`
(pybind11) e pelos executáveis (`gk-cli`, `gk-scanworker`) chamados como subprocessos.

```bash
pytest -q                 # tudo que for possível na plataforma atual
pytest -q tests/native    # núcleo C++ (requer o build)
```

## Núcleo (Agente A)
* `tests/foundation/` — fundação Python.
* `tests/native/` — unitários e **testes de equivalência** C++ × implementação Python de referência
  (`hashlib`, `filetypes.py`, `pefile`, `yara-python`) em corpus gerado.
* Fuzzing por mutação dos parsers (marcador `fuzz`), executado no build ASan.
* Testes que exigem Windows usam o marcador `windows_only` e rodam no CI Windows.

## Motor de testes (Agente B)

O pytest também compila e executa os componentes C++ do B (`native/ipc`, `native/updates`) via
`tests/integration/native_build.py` (CMake; Ninja no Linux, Visual Studio no Windows).

| Pasta | Conteúdo |
|---|---|
| `tests/helper/` | envelope IPC e quadros; processo auxiliar **real** com falhas provocadas (`fault_helper.py`: exceção, *crash* duro, travamento, escrita no stdout, resultado gigante, rede); relatórios (conteúdo das 15 seções, cracks, redação de dados pessoais, escape/CSP, PDF, banco somente leitura); sandbox (recusa sem isolamento, `.wsb`, fluxo com duplo da VM, mapeamento de comportamento, `monitor.ps1` estático); auxiliar congelado (`GK_FROZEN_HELPER`) |
| `tests/integration/` | **Python × C++**: pacotes `.gkpkg` (válidos, adulterações, 27 manifestos assinados porém inválidos, 60 mutações aleatórias, mesma decisão e mesmo código), instalador C++ (atômico, *downgrade*, validação, rollback, recuperação após queda de energia, trava), IOC e YARA (yara-python × libyara), ferramentas do publicador ponta a ponta, **cliente C++/Qt contra o auxiliar Python real** |
| `tests/corpus/` | dados de teste gerados (`sample_scan.py`: varredura realista gravada no banco) |

Variáveis:

| Variável | Efeito |
|---|---|
| `GK_NATIVE_REQUIRED=1` | toolchain nativo ausente = falha, e não pulo (CI) |
| `GK_NATIVE_SANITIZE=1` | compila variantes ASan + UBSan (`build/*-asan`) e roda a suíte contra elas; códigos de saída 99/98 separam erro de memória de rejeição legítima |
| `GK_CMAKE_ARGS` | argumentos extras do CMake (ex.: *toolchain* do vcpkg e caminho do Qt no Windows) |
| `GK_FROZEN_HELPER` | caminho do `gk-helper` congelado para o teste de fumaça |

Dependências de sistema (Linux): `cmake ninja-build g++ pkg-config qt6-base-dev libgl-dev libsodium-dev libyara-dev`.

Regras: amostras perigosas são geradas em tempo de teste; nenhum teste usa a rede; o lado da VM da sandbox é
substituído por um duplo de teste (nada é executado).
