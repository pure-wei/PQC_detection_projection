param(
    [ValidateSet('inspect', 'install', 'remove')]
    [string]$Action = 'inspect'
)
$ErrorActionPreference = 'Stop'
$pqcCertificatePath = Join-Path $PSScriptRoot 'public\root.cert.pem'
$pqcPem = [IO.File]::ReadAllText($pqcCertificatePath)
$pqcBase64 = $pqcPem.Replace('-----BEGIN CERTIFICATE-----', '').Replace('-----END CERTIFICATE-----', '')
$pqcDer = [Convert]::FromBase64String($pqcBase64)
$pqcCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pqcDer)
$pqcHasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $pqcSha256 = ([BitConverter]::ToString($pqcHasher.ComputeHash($pqcDer))).Replace('-', '')
} finally {
    $pqcHasher.Dispose()
}
Write-Output ('Subject: ' + $pqcCertificate.Subject)
Write-Output ('SHA256:  ' + $pqcSha256)
Write-Output ('SHA1:    ' + $pqcCertificate.Thumbprint)
Write-Output ('Expires: ' + $pqcCertificate.NotAfter.ToString('o'))
Write-Output 'Scope: Windows CurrentUser Root certificate store. This root can authorize certificates signed by this laboratory CA.'
if ($Action -eq 'install') {
    & certutil.exe -user -addstore Root $pqcCertificatePath
    if ($LASTEXITCODE -ne 0) { throw 'Certificate import failed.' }
} elseif ($Action -eq 'remove') {
    & certutil.exe -user -delstore Root $pqcCertificate.Thumbprint
    if ($LASTEXITCODE -ne 0) { throw 'Certificate removal failed.' }
}
