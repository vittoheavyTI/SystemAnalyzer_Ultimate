# Install.ps1 - System Analyzer Ultimate
# Script de instalação e execução automática

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "      SYSTEM ANALYZER ULTIMATE - INSTALADOR" -ForegroundColor Yellow
Write-Host "          Infratech Tecnologia" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# URL do script principal
$scriptUrl = "https://raw.githubusercontent.com/vittcheavyTI/SystemAnalyzer_Ultimate/main/SystemAnalyzer_Ultimate.ps1"
$localPath = "$env:TEMP\SystemAnalyzer_Ultimate.ps1"

try {
    Write-Host "📥 Baixando System Analyzer Ultimate..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $scriptUrl -OutFile $localPath -ErrorAction Stop
    
    if (Test-Path $localPath) {
        Write-Host "✅ Script baixado com sucesso!" -ForegroundColor Green
        Write-Host "🚀 Iniciando análise do sistema..." -ForegroundColor Cyan
        Write-Host ""
        
        # Executar o script com menu interativo
        & $localPath
    } else {
        Write-Host "❌ Erro: Script não foi baixado corretamente" -ForegroundColor Red
    }
    
} catch {
    Write-Host "❌ Erro ao baixar o script: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📞 Verifique a conexão com a internet ou tente novamente mais tarde" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Para executar novamente, use:" -ForegroundColor Green
Write-Host 'irm https://raw.githubusercontent.com/vittcheavyTI/SystemAnalyzer_Ultimate/main/Install.ps1 | iex' -ForegroundColor Yellow
Write-Host ""
Write-Host "Suporte: (77) 9 9853-9572 - Infratech Tecnologia" -ForegroundColor Cyan
