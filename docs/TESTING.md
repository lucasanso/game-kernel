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
Seção mantida pelo Agente B (integração, regressão, desempenho, falsos positivos, corpus).
