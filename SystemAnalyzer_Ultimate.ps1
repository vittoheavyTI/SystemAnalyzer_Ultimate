# SystemAnalyzer_Ultimate.ps1
# Analisador Completo do Sistema - PowerShell Version
# Desenvolvido por: Infratech Soluções em Som e Tecnologia
# Contato: (77) 9 9853-9572
# GitHub: https://github.com/vittcheavyTI/SystemAnalyzer_Ultimate

# Configurações iniciais
$global:ReportData = @{}
$global:IssuesFound = @()
$global:FixesApplied = @()
$global:StartTime = Get-Date

# Função para exibir banner
function Show-Banner {
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "      SYSTEM ANALYZER ULTIMATE - PowerShell" -ForegroundColor Yellow
    Write-Host "         Analisador Completo do Sistema" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Função para exibir menu
function Show-Menu {
    do {
        Clear-Host
        Show-Banner
        Write-Host "MENU PRINCIPAL:" -ForegroundColor Cyan
        Write-Host "1. Análise Completa do Sistema" -ForegroundColor White
        Write-Host "2. Apenas Diagnóstico (Sem Correções)" -ForegroundColor White
        Write-Host "3. Apenas Correções Automáticas" -ForegroundColor White
        Write-Host "4. Monitoramento em Tempo Real" -ForegroundColor White
        Write-Host "5. Sair" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "Selecione uma opção (1-5)"
        
        switch ($choice) {
            "1" { 
                Start-CompleteAnalysis 
                break
            }
            "2" { 
                Start-DiagnosisOnly 
                break
            }
            "3" { 
                Start-FixesOnly 
                break
            }
            "4" { 
                Start-RealTimeMonitor 
                break
            }
            "5" { 
                Write-Host "Saindo..." -ForegroundColor Yellow
                return
            }
            default { 
                Write-Host "Opção inválida! Pressione qualquer tecla para continuar..." -ForegroundColor Red
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
        
        if ($choice -ne "5") {
            Write-Host "`nPressione qualquer tecla para voltar ao menu..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } while ($choice -ne "5")
}

# Função para verificar permissões administrativas
function Test-AdminPermissions {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 1. ANÁLISE DE HARDWARE DETALHADA
function Analyze-Hardware {
    Write-Host "`n[1/8] Analisando Hardware..." -ForegroundColor Green
    
    $hardwareInfo = @{}
    
    try {
        # Informações do Sistema
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $hardwareInfo.System = @{
            Type = if ($computerSystem.PCSystemType -eq 2) { "Notebook" } else { "Desktop" }
            Manufacturer = $computerSystem.Manufacturer
            Model = $computerSystem.Model
        }
        
        # Informações da Placa Mãe
        $motherboard = Get-WmiObject -Class Win32_BaseBoard
        $hardwareInfo.Motherboard = @{
            Manufacturer = $motherboard.Manufacturer
            Product = $motherboard.Product
            Version = $motherboard.Version
        }
        
        # Informações da CPU
        $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        $hardwareInfo.CPU = @{
            Name = $cpu.Name
            Manufacturer = $cpu.Manufacturer
            Cores = $cpu.NumberOfCores
            LogicalProcessors = $cpu.NumberOfLogicalProcessors
            MaxClockSpeed = "$([math]::Round($cpu.MaxClockSpeed/1000, 2)) GHz"
            CurrentClockSpeed = "$([math]::Round($cpu.CurrentClockSpeed/1000, 2)) GHz"
            Architecture = switch ($cpu.Architecture) {
                0 { "x86" }
                1 { "MIPS" }
                2 { "Alpha" }
                3 { "PowerPC" }
                6 { "Itanium" }
                9 { "x64" }
                default { "Desconhecido" }
            }
        }
        
        # Informações de Memória Detalhadas
        $memory = Get-WmiObject -Class Win32_PhysicalMemory
        $totalMemory = ($memory | Measure-Object -Property Capacity -Sum).Sum / 1GB
        $memoryModules = @()
        
        foreach ($mem in $memory) {
            $memoryModules += @{
                Manufacturer = $mem.Manufacturer
                PartNumber = $mem.PartNumber
                CapacityGB = [math]::Round($mem.Capacity / 1GB, 2)
                Speed = "$($mem.Speed) MHz"
                MemoryType = switch ($mem.MemoryType) {
                    20 { "DDR" }
                    21 { "DDR2" }
                    24 { "DDR3" }
                    26 { "DDR4" }
                    34 { "DDR5" }
                    default { "Desconhecido ($($mem.MemoryType))" }
                }
            }
        }
        
        $hardwareInfo.Memory = @{
            TotalGB = [math]::Round($totalMemory, 2)
            Modules = $memory.Count
            ModulesDetail = $memoryModules
        }
        
        # Informações de Disco Detalhadas
        $disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
        $physicalDisks = Get-WmiObject -Class Win32_DiskDrive
        $diskInfo = @()
        
        foreach ($disk in $disks) {
            $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $totalSpaceGB = [math]::Round($disk.Size / 1GB, 2)
            $usagePercent = [math]::Round(($totalSpaceGB - $freeSpaceGB) / $totalSpaceGB * 100, 2)
            
            $physicalDisk = $physicalDisks | Where-Object {$_.DeviceID -like "*$($disk.DeviceID[0])*"}
            $diskType = if ($physicalDisk.Model -like "*SSD*") { "SSD" } 
                       elseif ($physicalDisk.Model -like "*NVMe*") { "M.2 NVMe" }
                       else { "HDD" }
            
            $diskInfo += @{
                Drive = $disk.DeviceID
                Model = $physicalDisk.Model
                Type = $diskType
                TotalGB = $totalSpaceGB
                FreeGB = $freeSpaceGB
                UsagePercent = $usagePercent
            }
            
            # Verificar espaço crítico
            if ($usagePercent -gt 90) {
                $global:IssuesFound += @{
                    Level = "CRITICAL"
                    Category = "Hardware"
                    Description = "Disco $($disk.DeviceID) com $usagePercent% de uso"
                    Solution = "Limpar arquivos temporários e desnecessários"
                }
            }
        }
        $hardwareInfo.Disks = $diskInfo
        
        # Informações da Placa de Vídeo Detalhadas
        $gpus = Get-WmiObject -Class Win32_VideoController | Where-Object {$_.Name -notlike "*Remote*"}
        $gpuInfo = @()
        
        foreach ($gpu in $gpus) {
            $vramGB = [math]::Round($gpu.AdapterRAM/1GB, 2)
            $gpuInfo += @{
                Name = $gpu.Name
                Manufacturer = $gpu.AdapterCompatibility
                VRAM = "$vramGB GB"
                DriverVersion = $gpu.DriverVersion
                DriverDate = $gpu.DriverDate
                CurrentResolution = "$($gpu.CurrentHorizontalResolution)x$($gpu.CurrentVerticalResolution)"
            }
        }
        $hardwareInfo.GPU = $gpuInfo
        
    } catch {
        Write-Host "Erro na análise de hardware: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $hardwareInfo
}

# 2. ANÁLISE DE SISTEMA OPERACIONAL
function Analyze-OperatingSystem {
    Write-Host "`n[2/8] Analisando Sistema Operacional..." -ForegroundColor Green
    
    $osInfo = @{}
    
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $osInfo.OS = @{
            Name = "$($os.Caption) $($os.OSArchitecture)"
            Version = $os.Version
            Build = $os.BuildNumber
            InstallDate = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
            LastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
            SerialNumber = $os.SerialNumber
        }
        
        # Verificar atualizações pendentes
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            
            $osInfo.Updates = @{
                Pending = $searchResult.Updates.Count
                Important = ($searchResult.Updates | Where-Object {$_.MsrcSeverity -eq "Important"}).Count
            }
            
            if ($searchResult.Updates.Count -gt 10) {
                $global:IssuesFound += @{
                    Level = "HIGH"
                    Category = "Sistema Operacional"
                    Description = "$($searchResult.Updates.Count) atualizações pendentes"
                    Solution = "Executar Windows Update"
                }
            }
        } catch {
            $osInfo.Updates = @{ Pending = "Não foi possível verificar"; Important = "N/A" }
        }
        
        # Verificar integridade do sistema
        $sfcResult = sfc /verifyonly 2>&1
        if ($sfcResult -like "*violações de integridade*") {
            $global:IssuesFound += @{
                Level = "HIGH"
                Category = "Sistema Operacional"
                Description = "Arquivos do sistema corrompidos detectados"
                Solution = "Executar 'sfc /scannow' como administrador"
            }
        }
        
    } catch {
        Write-Host "Erro na análise do SO: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $osInfo
}

# 3. ANÁLISE DE SOFTWARES INSTALADOS
function Analyze-Software {
    Write-Host "`n[3/8] Analisando Softwares Instalados..." -ForegroundColor Green
    
    $softwareInfo = @()
    
    try {
        $software = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate | Sort-Object Name
        
        foreach ($app in $software) {
            $softwareInfo += @{
                Name = $app.Name
                Version = $app.Version
                Vendor = $app.Vendor
                InstallDate = if ($app.InstallDate) { $app.InstallDate.Substring(0,8) } else { "N/A" }
            }
        }
        
        # Também verificar programas do registro
        $registrySoftware = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                           Where-Object {$_.DisplayName} |
                           Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        
        foreach ($app in $registrySoftware) {
            if ($softwareInfo.Name -notcontains $app.DisplayName) {
                $softwareInfo += @{
                    Name = $app.DisplayName
                    Version = $app.DisplayVersion
                    Vendor = $app.Publisher
                    InstallDate = $app.InstallDate
                }
            }
        }
        
    } catch {
        Write-Host "Erro na análise de software: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $softwareInfo
}

# 4. ANÁLISE DE DRIVERS
function Analyze-Drivers {
    Write-Host "`n[4/8] Analisando Drivers..." -ForegroundColor Green
    
    $driverInfo = @{}
    $problematicDrivers = @()
    
    try {
        $drivers = Get-WmiObject -Class Win32_PnPSignedDriver | Where-Object {$_.DeviceName -ne $null}
        
        foreach ($driver in $drivers) {
            if ($driver.IsSigned -eq $false) {
                $problematicDrivers += @{
                    Device = $driver.DeviceName
                    Driver = $driver.DriverVersion
                    Status = "Não Assinado"
                }
            }
        }
        
        $driverInfo.TotalDrivers = $drivers.Count
        $driverInfo.UnsignedDrivers = $problematicDrivers.Count
        $driverInfo.ProblematicDrivers = $problematicDrivers
        
        if ($problematicDrivers.Count -gt 0) {
            $global:IssuesFound += @{
                Level = "MEDIUM"
                Category = "Drivers"
                Description = "$($problematicDrivers.Count) drivers não assinados"
                Solution = "Atualizar drivers problemáticos"
            }
        }
        
        # Verificar dispositivos com problemas
        $problemDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object {$_.Status -ne "OK" -and $_.Status -ne "Unknown"}
        if ($problemDevices) {
            $global:IssuesFound += @{
                Level = "HIGH"
                Category = "Drivers"
                Description = "Dispositivos com problemas de configuração"
                Solution = "Verificar gerenciador de dispositivos"
            }
        }
        
    } catch {
        Write-Host "Erro na análise de drivers: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $driverInfo
}

# 5. ANÁLISE DE PERFORMANCE
function Analyze-Performance {
    Write-Host "`n[5/8] Analisando Performance..." -ForegroundColor Green
    
    $performanceInfo = @{}
    
    try {
        # Uso de CPU
        $cpuUsage = (Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        $performanceInfo.CPUUsage = "$cpuUsage%"
        
        # Uso de Memória
        $memory = Get-WmiObject -Class Win32_OperatingSystem
        $usedMemory = ($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / 1MB
        $totalMemory = $memory.TotalVisibleMemorySize / 1MB
        $memoryUsage = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
        $performanceInfo.MemoryUsage = "$memoryUsage%"
        
        # Processos problemáticos
        $heavyProcesses = Get-Process | Where-Object {$_.CPU -gt 50 -or $_.WorkingSet -gt 500MB} | 
                         Select-Object Name, CPU, @{Name="Memory(MB)"; Expression={[math]::Round($_.WorkingSet/1MB, 2)}} |
                         Sort-Object CPU -Descending | Select-Object -First 10
        
        $performanceInfo.HeavyProcesses = $heavyProcesses
        
        # Verificar problemas de performance
        if ($cpuUsage -gt 80) {
            $global:IssuesFound += @{
                Level = "HIGH"
                Category = "Performance"
                Description = "Uso de CPU muito alto: $cpuUsage%"
                Solution = "Verificar processos pesados"
            }
        }
        
        if ($memoryUsage -gt 90) {
            $global:IssuesFound += @{
                Level = "HIGH"
                Category = "Performance"
                Description = "Uso de memória muito alto: $memoryUsage%"
                Solution = "Fechar aplicações desnecessárias"
            }
        }
        
    } catch {
        Write-Host "Erro na análise de performance: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $performanceInfo
}

# 6. ANÁLISE DE SEGURANÇA
function Analyze-Security {
    Write-Host "`n[6/8] Analisando Segurança..." -ForegroundColor Green
    
    $securityInfo = @{}
    
    try {
        # Verificar antivírus
        $antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($antivirus) {
            $securityInfo.Antivirus = @{
                Name = $antivirus.displayName
                Status = if ($antivirus.productState -eq 266240) { "Ativo" } else { "Inativo" }
            }
        } else {
            $securityInfo.Antivirus = "Não detectado"
            $global:IssuesFound += @{
                Level = "CRITICAL"
                Category = "Segurança"
                Description = "Antivírus não detectado"
                Solution = "Instalar solução antivírus"
            }
        }
        
        # Verificar firewall
        $firewall = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq "True"}
        $securityInfo.Firewall = @{
            Domain = $firewall[0].Enabled
            Private = $firewall[1].Enabled
            Public = $firewall[2].Enabled
        }
        
        # Verificar Windows Defender
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            $securityInfo.Defender = @{
                AntivirusEnabled = $defender.AntivirusEnabled
                RealTimeProtection = $defender.RealTimeProtectionEnabled
                LastScan = $defender.LastQuickScanDateTime
            }
        }
        
        # Verificar usuários sem senha
        $users = Get-WmiObject -Class Win32_UserAccount | Where-Object {$_.PasswordRequired -eq $false -and $_.Disabled -eq $false}
        if ($users) {
            $global:IssuesFound += @{
                Level = "HIGH"
                Category = "Segurança"
                Description = "Usuários sem senha requerida"
                Solution = "Configurar senhas obrigatórias"
            }
        }
        
    } catch {
        Write-Host "Erro na análise de segurança: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $securityInfo
}

# 7. ANÁLISE DE REDE
function Analyze-Network {
    Write-Host "`n[7/8] Analisando Rede..." -ForegroundColor Green
    
    $networkInfo = @{}
    
    try {
        # Configurações de rede
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        $networkInfo.Adapters = $adapters | ForEach-Object {
            @{
                Name = $_.Name
                Interface = $_.InterfaceDescription
                Speed = "$($_.LinkSpeed) Mbps"
                Status = $_.Status
            }
        }
        
        # Configurações IP
        $ipConfig = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.PrefixOrigin -eq "Dhcp"} | Select-Object -First 1
        $networkInfo.IPConfig = @{
            IPAddress = $ipConfig.IPAddress
            Gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
        }
        
        # Teste de conectividade
        $pingTest = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet
        $networkInfo.InternetConnectivity = if ($pingTest) { "OK" } else { "FALHA" }
        
        if (-not $pingTest) {
            $global:IssuesFound += @{
                Level = "MEDIUM"
                Category = "Rede"
                Description = "Problemas de conectividade com a internet"
                Solution = "Verificar configurações de rede e DNS"
            }
        }
        
        # DNS
        $dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -eq "Ethernet" -or $_.InterfaceAlias -eq "Wi-Fi"}).ServerAddresses
        $networkInfo.DNSServers = $dnsServers
        
    } catch {
        Write-Host "Erro na análise de rede: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $networkInfo
}

# 8. CORREÇÕES AUTOMÁTICAS
function Apply-AutoFixes {
    Write-Host "`n[8/8] Aplicando Correções Automáticas..." -ForegroundColor Yellow
    
    $fixResults = @()
    
    # Limpeza de arquivos temporários
    try {
        Write-Host "  - Limpando arquivos temporários..." -NoNewline
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host " [OK]" -ForegroundColor Green
        $fixResults += "Arquivos temporários limpos"
    } catch {
        Write-Host " [FALHA]" -ForegroundColor Red
    }
    
    # Limpeza do cache do DNS
    try {
        Write-Host "  - Limpando cache DNS..." -NoNewline
        Clear-DnsClientCache
        Write-Host " [OK]" -ForegroundColor Green
        $fixResults += "Cache DNS limpo"
    } catch {
        Write-Host " [FALHA]" -ForegroundColor Red
    }
    
    # Reparar arquivos do sistema
    if (Test-AdminPermissions) {
        try {
            Write-Host "  - Verificando integridade do sistema..." -NoNewline
            $sfcResult = Start-Process -FilePath "sfc" -ArgumentList "/scannow" -Wait -PassThru -NoNewWindow
            if ($sfcResult.ExitCode -eq 0) {
                Write-Host " [OK]" -ForegroundColor Green
                $fixResults += "Verificação SFC concluída"
            } else {
                Write-Host " [REPARADO]" -ForegroundColor Yellow
                $fixResults += "Arquivos do sistema reparados"
            }
        } catch {
            Write-Host " [FALHA]" -ForegroundColor Red
        }
    }
    
    # Otimização de disco
    try {
        Write-Host "  - Otimizando unidades..." -NoNewline
        Optimize-Volume -DriveLetter C -ReTrim -ErrorAction SilentlyContinue
        Write-Host " [OK]" -ForegroundColor Green
        $fixResults += "Otimização de disco realizada"
    } catch {
        Write-Host " [FALHA]" -ForegroundColor Red
    }
    
    return $fixResults
}

# GERAR RELATÓRIO HTML MELHORADO
function Generate-Report {
    Write-Host "`n[+] Gerando Relatório Completo..." -ForegroundColor Green
    
    $endTime = Get-Date
    $duration = $endTime - $global:StartTime
    
    # Relatório em HTML com informações da empresa
    $htmlReport = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório System Analyzer Ultimate - Infratech</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white; 
            padding: 30px; 
            text-align: center;
            position: relative;
        }
        .company-info {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 3px solid #3498db;
            text-align: center;
        }
        .company-info .contact {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 10px;
        }
        .company-info .contact div {
            padding: 8px 15px;
            background: #e3f2fd;
            border-radius: 20px;
            font-size: 14px;
        }
        .section { 
            margin: 25px; 
            padding: 25px; 
            border: 1px solid #e0e0e0; 
            border-radius: 10px;
            background: #fff;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .critical { background: #ffebee; border-left: 5px solid #f44336; }
        .high { background: #fff3e0; border-left: 5px solid #ff9800; }
        .medium { background: #fff9c4; border-left: 5px solid #ffeb3b; }
        .low { background: #e8f5e8; border-left: 5px solid #4caf50; }
        .fixed { background: #e3f2fd; border-left: 5px solid #2196f3; }
        .info { background: #f3e5f5; border-left: 5px solid #9c27b0; }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 15px 0;
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: 600;
        }
        tr:hover { background-color: #f5f5f5; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #2c3e50; margin-bottom: 15px; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        h3 { color: #34495e; margin: 15px 0 10px 0; }
        .print-btn {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #27ae60;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: all 0.3s ease;
        }
        .print-btn:hover {
            background: #219a52;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #3498db;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 5px;
        }
        .badge.critical { background: #f44336; color: white; }
        .badge.high { background: #ff9800; color: white; }
        .badge.medium { background: #ffeb3b; color: #333; }
        .badge.low { background: #4caf50; color: white; }
        .timestamp {
            text-align: center;
            color: #7f8c8d;
            font-style: italic;
            margin: 10px 0;
        }
        @media print {
            .print-btn { display: none; }
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <button class="print-btn" onclick="window.print()">🖨️ Imprimir Relatório</button>
    
    <div class="container">
        <div class="header">
            <h1>🔧 System Analyzer Ultimate</h1>
            <p>Relatório Completo de Análise do Sistema</p>
        </div>
        
        <div class="company-info">
            <h3>Infratech Tecnologia</h3>
            <div class="contact">
                <div>📞 (77) 9 9853-9572</div>
                <div>📍 Rua Mato Grosso, Nº750, Apto 02, Centro, Luís Eduardo Magalhães - BA</div>
                <div>🌐 www.infratechtecnologia.com.br</div>
                <div>✉️ infratechtecnologia@hotmail.com</div>
                <div>📷 @Infratech Tecnologia</div>
                <div>👥 Infratech Tecnologia</div>
            </div>
        </div>

        <div class="timestamp">
            Relatório gerado em: $(Get-Date -Format "dd/MM/yyyy 'às' HH:mm:ss") | 
            Tempo de análise: $([math]::Round($duration.TotalMinutes, 2)) minutos
        </div>

        <div class="section">
            <h2>📊 Resumo do Sistema</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>🖥️ Hardware</h3>
                    <p><strong>Tipo:</strong> $($global:ReportData.Hardware.System.Type)</p>
                    <p><strong>Marca/Modelo:</strong> $($global:ReportData.Hardware.System.Manufacturer) $($global:ReportData.Hardware.System.Model)</p>
                    <p><strong>Processador:</strong> $($global:ReportData.Hardware.CPU.Name)</p>
                    <p><strong>Memória RAM:</strong> $($global:ReportData.Hardware.Memory.TotalGB) GB</p>
                    <p><strong>Placa de Vídeo:</strong> $(if ($global:ReportData.Hardware.GPU.Count -gt 0) { $global:ReportData.Hardware.GPU[0].Name } else { "Integrada" })</p>
                </div>
                
                <div class="summary-card">
                    <h3>⚙️ Sistema Operacional</h3>
                    <p><strong>SO:</strong> $($global:ReportData.OS.OS.Name)</p>
                    <p><strong>Versão:</strong> $($global:ReportData.OS.OS.Version)</p>
                    <p><strong>Build:</strong> $($global:ReportData.OS.OS.Build)</p>
                    <p><strong>Instalação:</strong> $($global:ReportData.OS.OS.InstallDate.ToString("dd/MM/yyyy"))</p>
                    <p><strong>Atualizações Pendentes:</strong> $($global:ReportData.OS.Updates.Pending)</p>
                </div>
                
                <div class="summary-card">
                    <h3>📈 Performance</h3>
                    <p><strong>Uso de CPU:</strong> $($global:ReportData.Performance.CPUUsage)</p>
                    <p><strong>Uso de Memória:</strong> $($global:ReportData.Performance.MemoryUsage)</p>
                    <p><strong>Antivírus:</strong> $(if ($global:ReportData.Security.Antivirus -ne "Não detectado") { $global:ReportData.Security.Antivirus.Name } else { "Não detectado" })</p>
                    <p><strong>Internet:</strong> $($global:ReportData.Network.InternetConnectivity)</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🔍 Problemas Encontrados</h2>
            $(if ($global:IssuesFound.Count -gt 0) {
                "<table>
                    <tr><th>Nível</th><th>Categoria</th><th>Descrição</th><th>Solução</th></tr>"
                foreach ($issue in $global:IssuesFound) {
                    $levelClass = $issue.Level.ToLower()
                    "<tr class='$levelClass'>
                        <td><span class='badge $levelClass'>$($issue.Level)</span></td>
                        <td>$($issue.Category)</td>
                        <td>$($issue.Description)</td>
                        <td>$($issue.Solution)</td>
                    </tr>"
                }
                "</table>"
            } else {
                "<p style='text-align: center; color: #27ae60; font-size: 18px; padding: 20px;'>✅ Nenhum problema crítico encontrado! O sistema está em bom estado.</p>"
            })
        </div>

        <div class="section fixed">
            <h2>🔧 Correções Aplicadas</h2>
            $(if ($global:FixesApplied.Count -gt 0) {
                "<ul style='list-style-type: none; padding: 0;'>"
                foreach ($fix in $global:FixesApplied) {
                    "<li style='padding: 8px 0; border-bottom: 1px solid #e0e0e0;'>✅ $fix</li>"
                }
                "</ul>"
            } else {
                "<p style='text-align: center; color: #7f8c8d;'>Nenhuma correção automática foi aplicada.</p>"
            })
        </div>

        <div class="section info">
            <h2>🖥️ Detalhes do Hardware</h2>
            <h3>Processador</h3>
            <p><strong>Modelo:</strong> $($global:ReportData.Hardware.CPU.Name)</p>
            <p><strong>Núcleos:</strong> $($global:ReportData.Hardware.CPU.Cores) físicos, $($global:ReportData.Hardware.CPU.LogicalProcessors) lógicos</p>
            <p><strong>Clock:</strong> $($global:ReportData.Hardware.CPU.CurrentClockSpeed) (Max: $($global:ReportData.Hardware.CPU.MaxClockSpeed))</p>
            
            <h3>Memória RAM</h3>
            <p><strong>Total:</strong> $($global:ReportData.Hardware.Memory.TotalGB) GB em $($global:ReportData.Hardware.Memory.Modules) módulo(s)</p>
            $(if ($global:ReportData.Hardware.Memory.ModulesDetail.Count -gt 0) {
                "<table><tr><th>Marca</th><th>Modelo</th><th>Capacidade</th><th>Velocidade</th><th>Tipo</th></tr>"
                foreach ($mem in $global:ReportData.Hardware.Memory.ModulesDetail) {
                    "<tr>
                        <td>$($mem.Manufacturer)</td>
                        <td>$($mem.PartNumber)</td>
                        <td>$($mem.CapacityGB) GB</td>
                        <td>$($mem.Speed)</td>
                        <td>$($mem.MemoryType)</td>
                    </tr>"
                }
                "</table>"
            })
            
            <h3>Armazenamento</h3>
            $(if ($global:ReportData.Hardware.Disks.Count -gt 0) {
                "<table><tr><th>Unidade</th><th>Modelo</th><th>Tipo</th><th>Capacidade</th><th>Livre</th><th>Uso</th></tr>"
                foreach ($disk in $global:ReportData.Hardware.Disks) {
                    "<tr>
                        <td>$($disk.Drive)</td>
                        <td>$($disk.Model)</td>
                        <td>$($disk.Type)</td>
                        <td>$($disk.TotalGB) GB</td>
                        <td>$($disk.FreeGB) GB</td>
                        <td>$($disk.UsagePercent)%</td>
                    </tr>"
                }
                "</table>"
            })
            
            <h3>Placa de Vídeo</h3>
            $(if ($global:ReportData.Hardware.GPU.Count -gt 0) {
                foreach ($gpu in $global:ReportData.Hardware.GPU) {
                    "<p><strong>Modelo:</strong> $($gpu.Name)</p>"
                    "<p><strong>VRAM:</strong> $($gpu.VRAM)</p>"
                    "<p><strong>Driver:</strong> $($gpu.DriverVersion) ($($gpu.DriverDate))</p>"
                    "<p><strong>Resolução:</strong> $($gpu.CurrentResolution)</p><hr>"
                }
            } else {
                "<p>Placa de vídeo integrada</p>"
            })
        </div>

        <div class="section info">
            <h2>📦 Softwares Instalados</h2>
            $(if ($global:ReportData.Software.Count -gt 0) {
                "<table><tr><th>Nome</th><th>Versão</th><th>Fabricante</th><th>Data Instalação</th></tr>"
                foreach ($software in $global:ReportData.Software | Sort-Object Name) {
                    "<tr>
                        <td>$($software.Name)</td>
                        <td>$($software.Version)</td>
                        <td>$($software.Vendor)</td>
                        <td>$($software.InstallDate)</td>
                    </tr>"
                }
                "</table>"
            } else {
                "<p>Não foi possível obter a lista de softwares instalados.</p>"
            })
        </div>

        <div class="section">
            <h2>📞 Recomendações e Suporte</h2>
            <p>Para suporte técnico especializado, entre em contato com a <strong>Infratech Tecnologia</strong>:</p>
            <div style='text-align: center; margin: 20px 0;'>
                <div style='background: #e3f2fd; padding: 15px; border-radius: 10px; display: inline-block;'>
                    <strong>📞 (77) 9 9853-9572</strong><br>
                    <strong>📍 Rua Mato Grosso, Nº750, Apto 02, Centro</strong><br>
                    <strong>Luís Eduardo Magalhães - BA</strong>
                </div>
            </div>
            <p style='text-align: center; margin-top: 20px;'>
                <em>Relatório gerado automaticamente pelo System Analyzer Ultimate</em>
            </p>
        </div>
    </div>

    <script>
        // Adicionar funcionalidade de impressão
        function printReport() {
            window.print();
        }
        
        // Destacar linhas da tabela
        document.addEventListener('DOMContentLoaded', function() {
            const rows = document.querySelectorAll('tr');
            rows.forEach(row => {
                row.addEventListener('mouseenter', function() {
                    this.style.backgroundColor = '#f0f8ff';
                });
                row.addEventListener('mouseleave', function() {
                    this.style.backgroundColor = '';
                });
            });
        });
    </script>
</body>
</html>
"@

    # Salvar relatório
    $reportPath = "$env:USERPROFILE\Desktop\SystemAnalyzer_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
    
    return $reportPath
}

# FUNÇÕES PRINCIPAIS
function Start-CompleteAnalysis {
    Clear-Host
    Show-Banner
    Write-Host "Iniciando análise completa do sistema..." -ForegroundColor Cyan
    
    # Executar todas as análises
    $global:ReportData.Hardware = Analyze-Hardware
    $global:ReportData.OS = Analyze-OperatingSystem
    $global:ReportData.Software = Analyze-Software
    $global:ReportData.Drivers = Analyze-Drivers
    $global:ReportData.Performance = Analyze-Performance
    $global:ReportData.Security = Analyze-Security
    $global:ReportData.Network = Analyze-Network
    
    # Aplicar correções automáticas
    $global:FixesApplied = Apply-AutoFixes
    
    # Gerar relatório
    $reportPath = Generate-Report
    
    Show-AnalysisSummary
    return $reportPath
}

function Start-DiagnosisOnly {
    Clear-Host
    Show-Banner
    Write-Host "Iniciando diagnóstico (sem correções)..." -ForegroundColor Cyan
    
    # Executar apenas análises
    $global:ReportData.Hardware = Analyze-Hardware
    $global:ReportData.OS = Analyze-OperatingSystem
    $global:ReportData.Software = Analyze-Software
    $global:ReportData.Drivers = Analyze-Drivers
    $global:ReportData.Performance = Analyze-Performance
    $global:ReportData.Security = Analyze-Security
    $global:ReportData.Network = Analyze-Network
    
    # Gerar relatório
    $reportPath = Generate-Report
    
    Show-AnalysisSummary
    return $reportPath
}

function Start-FixesOnly {
    Clear-Host
    Show-Banner
    Write-Host "Aplicando apenas correções automáticas..." -ForegroundColor Cyan
    
    $global:FixesApplied = Apply-AutoFixes
    
    Write-Host "`n✅ Correções aplicadas: $($global:FixesApplied.Count)" -ForegroundColor Green
    foreach ($fix in $global:FixesApplied) {
        Write-Host "   • $fix" -ForegroundColor White
    }
}

function Start-RealTimeMonitor {
    Clear-Host
    Show-Banner
    Write-Host "Monitoramento em Tempo Real" -ForegroundColor Cyan
    Write-Host "Pressione 'Q' para sair do monitoramento" -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $cpuUsage = (Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        $memory = Get-WmiObject -Class Win32_OperatingSystem
        $usedMemory = ($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / 1MB
        $totalMemory = $memory.TotalVisibleMemorySize / 1MB
        $memoryUsage = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
        
        Clear-Host
        Show-Banner
        Write-Host "Monitoramento em Tempo Real - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "CPU: $cpuUsage%" -ForegroundColor $(if ($cpuUsage -gt 80) { "Red" } else { "Green" })
        Write-Host "Memória: $memoryUsage%" -ForegroundColor $(if ($memoryUsage -gt 80) { "Red" } else { "Green" })
        Write-Host ""
        Write-Host "Processos mais pesados:" -ForegroundColor Yellow
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | Format-Table Name, CPU, @{Name="Memory(MB)"; Expression={[math]::Round($_.WorkingSet/1MB, 2)}} -AutoSize
        
        Start-Sleep -Seconds 2
    } until ($Host.UI.RawUI.KeyAvailable -and ($Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character -eq 'q'))
}

function Show-AnalysisSummary {
    Write-Host "`n" + "="*60 -ForegroundColor Green
    Write-Host "           ANÁLISE CONCLUÍDA COM SUCESSO!" -ForegroundColor Green
    Write-Host "="*60 -ForegroundColor Green
    
    Write-Host "`n📈 RESUMO DA ANÁLISE:" -ForegroundColor Cyan
    Write-Host "  • Problemas encontrados: $($global:IssuesFound.Count)" -ForegroundColor $(if ($global:IssuesFound.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  • Correções aplicadas: $($global:FixesApplied.Count)" -ForegroundColor Green
    Write-Host "  • Relatório salvo em: $($reportPath)" -ForegroundColor Yellow
    
    if ($global:IssuesFound.Count -gt 0) {
        Write-Host "`n⚠️  PROBLEMAS IDENTIFICADOS:" -ForegroundColor Red
        foreach ($issue in $global:IssuesFound) {
            $color = switch ($issue.Level) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Green" }
                default { "White" }
            }
            Write-Host "  [$($issue.Level)] $($issue.Description)" -ForegroundColor $color
        }
    }
    
    Write-Host "`n🚀 PRÓXIMOS PASSOS:" -ForegroundColor Cyan
    if ($global:IssuesFound.Count -eq 0) {
        Write-Host "  • Sistema está em bom estado!" -ForegroundColor Green
    } else {
        Write-Host "  • Verifique o relatório completo para soluções detalhadas" -ForegroundColor Yellow
        Write-Host "  • Execute as correções manuais sugeridas" -ForegroundColor Yellow
    }
    
    # Perguntar se deseja abrir o relatório
    $openReport = Read-Host "`nDeseja abrir o relatório agora? (S/N)"
    if ($openReport -eq "S" -or $openReport -eq "s") {
        Start-Process $reportPath
        Write-Host "Relatório aberto no navegador padrão." -ForegroundColor Green
    }
}

# INICIALIZAÇÃO DO SCRIPT
if ($MyInvocation.InvocationName -ne '.') {
    # Verificar se é para execução automática ou menu
    if ($args[0] -eq "-auto") {
        Write-Host "Execução automática ativada..." -ForegroundColor Yellow
        Start-CompleteAnalysis
    } else {
        # Mostrar menu interativo
        Show-Menu
    }
}
