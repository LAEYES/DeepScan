# Vérifier si le script est exécuté avec des privilèges administratifs
function Test-Admin {
    param (
        [string]$message = "Ce script nécessite des privilèges d'administrateur. Veuillez exécuter à nouveau en tant qu'administrateur."
    )
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error $message
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
        exit
    }
}

# Appeler la fonction pour tester les privilèges d'administrateur dès le début
Test-Admin

# Configuration
$logFile = "C:\TCPsystemSecureAutonomous\logs\securityLog.log"
$suspiciousIpsFile = "C:\TCPsystemSecureAutonomous\logs\suspiciousIps.txt"
$suspiciousFilesFile = "C:\TCPsystemSecureAutonomous\logs\suspiciousFiles.txt"
$alertEmail = "admin@example.com"
$smtpServer = "smtp.example.com"
$alertFrom = "alert@example.com"

# Créer les répertoires de journalisation s'ils n'existent pas
foreach ($path in @($logFile, $suspiciousIpsFile, $suspiciousFilesFile)) {
    $directory = Split-Path -Path $path -Parent
    if (-not (Test-Path -Path $directory)) {
        try {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        } catch {
            Write-Error "Échec de la création du répertoire ${directory}: $($_.Exception.Message). Veuillez vérifier les permissions."
        }
    }
}

# Fonction pour écrire dans le journal
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    try {
        Add-Content -Path $logFile -Value "${timestamp} - ${message}"
    } catch {
        Write-Error "Échec de l'écriture dans le journal: $($_.Exception.Message). Veuillez vérifier que le fichier est accessible."
    }
}

# Fonction pour envoyer un e-mail d'alerte
function Send-AlertEmail {
    param (
        [string]$subject,
        [string]$body
    )
    try {
        $emailMessage = New-Object system.net.mail.mailmessage
        $emailMessage.From = $alertFrom
        $emailMessage.To.Add($alertEmail)
        $emailMessage.Subject = $subject
        $emailMessage.Body = $body
        $smtp = New-Object Net.Mail.SmtpClient($smtpServer)
        $smtp.Send($emailMessage)
        Log-Message "E-mail d'alerte envoyé: ${subject}"
    } catch {
        Log-Message "Échec de l'envoi de l'e-mail d'alerte: $($_.Exception.Message). Vérifiez la configuration SMTP."
    }
}

# Fonction pour auditer les politiques de sécurité
function Audit-SecurityPolicies {
    $passwordPolicy = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge"
    Log-Message "Durée maximale de validité des mots de passe: $($passwordPolicy.MaximumPasswordAge)"
    
    $disabledAccounts = Get-LocalUser | Where-Object { $_.Enabled -eq $false }
    foreach ($account in $disabledAccounts) {
        Log-Message "Compte désactivé détecté: $($account.Name)"
    }
}

# Charger les IPs suspectes depuis le fichier
function Load-SuspiciousIps {
    if (Test-Path $suspiciousIpsFile) {
        return Get-Content -Path $suspiciousIpsFile
    }
    return @()
}

# Sauvegarder les IPs suspectes dans le fichier
function Save-SuspiciousIps {
    param (
        [string[]]$ips
    )
    try {
        $ips | Out-File -FilePath $suspiciousIpsFile -Encoding utf8 -NewLine -Force 
    } catch {
        Log-Message "Échec de la sauvegarde des IPs suspectes: $($_.Exception.Message). Vérifiez les permissions d'écriture sur le fichier."
    }
}

# Ajouter une IP à la liste et sauvegarder
function Add-SuspiciousIp {
    param (
        [string]$ipAddress
    )
    if ([System.Net.IPAddress]::TryParse($ipAddress, [ref]$null)) {
        $suspiciousIps = Load-SuspiciousIps
        if (-not ($suspiciousIps -contains $ipAddress)) {
            $suspiciousIps += $ipAddress
            Save-SuspiciousIps -ips $suspiciousIps
            Log-Message "IP suspecte ajoutée: ${ipAddress}"
            Send-AlertEmail -subject "Nouvelle IP suspecte ajoutée" -body "IP suspecte ajoutée: ${ipAddress}"
        }
    } else {
        Log-Message "Adresse IP invalide: ${ipAddress}. Veuillez fournir une adresse IP valide."
    }
}

function Monitor-FailedLogins {
    $failedLogins = Get-EventLog -LogName Security | Where-Object { $_.EventID -eq 4625 }
    foreach ($login in $failedLogins) {
        Log-Message "Tentative de connexion échouée détectée: $($login.ReplacementStrings[5]) sur $($login.TimeGenerated)"
        Send-AlertEmail -subject "Tentative de connexion échouée" -body "Tentative de connexion échouée par $($login.ReplacementStrings[5]) à $($login.TimeGenerated)"
    }
}

# Vérifier l'existence d'une règle de pare-feu
function Add-FirewallRuleIfNotExist {
    param (
        [string]$ipAddress
    )
    if (-not (Get-NetFirewallRule | Where-Object { $_.RemoteAddress -eq $ipAddress })) {
        try {
            Add-NetFirewallRule -DisplayName "Bloquer ${ipAddress}" -Direction Inbound -LocalPort All -Protocol TCP -RemoteAddress $ipAddress -Action Block
            Log-Message "Règle de pare-feu ajoutée pour IP: ${ipAddress}"
        } catch {
            Log-Message "Échec de l'ajout de la règle de pare-feu pour IP ${ipAddress}: $($_.Exception.Message). Assurez-vous que vous avez les droits administratifs."
        }
    } else {
        Log-Message "La règle de pare-feu existe déjà pour IP: ${ipAddress}"
    }
}

function Scan-WithWindowsDefender {
    param (
        [string]$filePath
    )
    
    try {
        Start-Process "MpCmdRun.exe" -ArgumentList "-Scan -ScanType 3 -File $filePath" -Wait -NoNewWindow
        Log-Message "Analyse Windows Defender effectuée sur le fichier: $filePath"
    } catch {
        Log-Message "Échec de l'analyse Windows Defender: $($_.Exception.Message)"
    }
}

# Fonction pour surveiller les connexions réseau
function Monitor-NetworkConnections {
    try {
        $connections = netstat -ano | Select-String -Pattern "ESTABLISHED"
        foreach ($connection in $connections) {
            $ipAddress = $connection -replace '.*(\d+\.\d+\.\d+\.\d+).*', '$1'
            if ($ipAddress) {
                Add-SuspiciousIp -ipAddress $ipAddress
                Add-FirewallRuleIfNotExist -ipAddress $ipAddress
            }
        }
    } catch {
        Log-Message "Erreur lors de la surveillance des connexions réseau: $($_.Exception.Message). Vérifiez si vous avez les droits d'exécution nécessaires."
    }
}

# Fonction pour surveiller les ports ouverts
function Monitor-OpenPorts {
    $allowedPorts = @("80", "443", "22")
    $openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }

    foreach ($port in $openPorts) {
        if (-not ($allowedPorts -contains $port.LocalPort)) {
            Log-Message "Port non autorisé détecté: $($port.LocalPort) utilisé par $($port.OwningProcess)"
            Add-FirewallRuleIfNotExist -ipAddress $port.RemoteAddress
        }
    }
}

# Fonction pour surveiller les processus
function Monitor-Processes {
    try {
        $suspiciousProcesses = @("maliciousProcess.exe", "unwantedApp.exe")
        foreach ($proc in $suspiciousProcesses) {
            $runningProcesses = Get-Process -Name $proc -ErrorAction SilentlyContinue
            foreach ($process in $runningProcesses) {
                Log-Message "Processus suspect détecté: $($process.Name) avec PID $($process.Id)"
                Stop-Process -Id $process.Id -Force
                Send-AlertEmail -subject "Processus suspect arrêté" -body "Processus suspect arrêté: $($process.Name) avec PID $($process.Id)"
            }
        }
    } catch {
        Log-Message "Erreur lors de la surveillance des processus: $($_.Exception.Message). Vérifiez que vous avez les droits d'accès nécessaires."
    }
}

# Fonction pour extraire les IPs suspectes du journal
function Extract-IPsFromLog {
    param (
        [string]$logFilePath,
        [string]$outputFilePath
    )
    
    try {
        $logContent = Get-Content -Path $logFilePath
        $ipPattern = '\b\d{1,3}(?:\.\d{1,3}){3}\b'
        $foundIPs = @()

        foreach ($line in $logContent) {
            if ($line -match $ipPattern) {
                $ipAddress = $matches[0]
                $foundIPs += $ipAddress
                Log-Message "IP trouvée dans le journal: ${ipAddress}"
            }
        }

        if ($foundIPs.Count -gt 0) {
            $foundIPs | Out-File -FilePath $outputFilePath -Encoding utf8 -Append -NewLine
            Log-Message "IPs extraites et ajoutées à ${outputFilePath}."
        } else {
            Log-Message "Aucune IP trouvée dans le journal."
        }
    } catch {
        Log-Message "Erreur lors de l'extraction des IPs: $($_.Exception.Message)"
    }
}

# Exécution des fonctions de surveillance
Monitor-FailedLogins
Monitor-NetworkConnections
Monitor-OpenPorts
Monitor-Processes
Audit-SecurityPolicies

# Exécuter l'extraction des IPs à partir du log
Extract-IPsFromLog -logFilePath $logFile -outputFilePath $suspiciousIpsFile
