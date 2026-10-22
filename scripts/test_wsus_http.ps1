$urls = @(
    "http://10.0.60.32:8530/",
    "http://10.0.60.32:8530/ClientWebService/client.asmx",
    "http://10.0.60.32:8530/SimpleAuthWebService/SimpleAuth.asmx",
    "http://10.0.60.32:8530/ApiRemoting30/WebService.asmx",
    "http://10.0.60.32:8530/ServerSyncWebService/ServerSyncWebService.asmx"
)

foreach ($u in $urls) {
    try {
        $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 5
        Write-Host "[OK $($r.StatusCode)] $u" -ForegroundColor Green
    } catch {
        $code = ""
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        Write-Host "[$code] $u - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
