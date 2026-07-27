# rxvscan — UI ImGui (réplica do FCSV)

Interface em Dear ImGui replicando o layout do print: barra de título custom,
seções **Services / HWID / System / BAM / Prefetch / USN Journal / Emulator**,
abas Terminal/Prefix e barra de status no rodapé.

## Arquivos
- `scanner_ui.h` — tema + modelo de dados (`ScanData`) + render. **É aqui que você
  pluga os dados reais do seu scanner.** Header-only.
- `main.cpp` — janela borderless + DirectX11 + ImGui (loop principal).

## Passo a passo pra compilar

1. **Baixar o Dear ImGui** (uma vez):
   ```powershell
   cd "c:\Users\nothz\OneDrive\Desktop\projetos\rxvscan\c++"
   git clone https://github.com/ocornut/imgui.git imgui
   ```
   (ou baixe o .zip e extraia numa pasta chamada `imgui` aqui dentro)

2. No Visual Studio, abra `c++.sln` e adicione ao projeto (Add > Existing Item),
   ou descomente as linhas já prontas no `c++.vcxproj`:
   - `imgui/imgui.cpp`
   - `imgui/imgui_draw.cpp`
   - `imgui/imgui_tables.cpp`
   - `imgui/imgui_widgets.cpp`
   - `imgui/backends/imgui_impl_win32.cpp`
   - `imgui/backends/imgui_impl_dx11.cpp`

3. **Já está configurado** no projeto:
   - Include dirs: `imgui` e `imgui\backends`
   - Libs `d3d11 / dxgi / d3dcompiler` (via `#pragma comment` no `main.cpp`)
   - SubSystem = Windows (pro `WinMain`)

4. Compile em **x64 / Debug** (ou Release). Pronto.

## Como ligar nos seus dados
No `main.cpp`:
```cpp
ScannerUI::ScanData data = ScannerUI::MakeSampleData(); // dados de exemplo
```
Troque por um `ScanData` que você preenche com os resultados reais do scan
(serviços, HWID, BAM, prefetch, etc). Os campos estão documentados no topo do
`scanner_ui.h`.

## Observações de fidelidade
- Os "✓/✗" são desenhados à mão (linhas) porque a fonte padrão do ImGui não tem
  esses glifos. Se quiser ícones bonitos (pasta, alerta, cópia), carregue uma
  fonte de ícones (ex.: Font Awesome via `IconsFontAwesome`).
- O botão de pasta no BAM abre o `explorer /select` no caminho do arquivo.
- Cores em `ScannerUI::col` — ajuste à vontade pra bater 100% com seu tema.
