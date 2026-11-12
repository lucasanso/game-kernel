# Assinaturas ClamAV locais

`gk_local.hdb` — assinaturas por hash (MD5:tamanho:nome) mantidas pelo Game Kernel. Hoje contém apenas o
arquivo de teste EICAR, para validar a integração com o ClamAV mesmo antes da importação dos bancos oficiais.

Os bancos oficiais (`main.cvd`, `daily.cvd`, `bytecode.cvd`) chegam por pacote de atualização offline
assinado e ficam em `<dados>/signatures/active/clamav/`; o ClamAV verifica a assinatura digital da Cisco Talos
de cada CVD ao carregá-lo. O `clamscan` recebe os dois diretórios (`-d`) numa única execução por lote.
