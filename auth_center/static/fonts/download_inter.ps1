# Inter 字体下载脚本（Windows PowerShell）
# 在 auth_center/static/fonts/ 目录下运行此脚本

$baseUrl = "https://github.com/rsms/inter/raw/master/docs/font-files"
$fonts = @{
    "Inter-Regular.woff2"   = "Inter-Regular.woff2"
    "Inter-Medium.woff2"    = "Inter-Medium.woff2"
    "Inter-SemiBold.woff2"  = "Inter-SemiBold.woff2"
    "Inter-Bold.woff2"      = "Inter-Bold.woff2"
    "Inter-ExtraBold.woff2" = "Inter-ExtraBold.woff2"
}

foreach ($font in $fonts.GetEnumerator()) {
    $url = "$baseUrl/$($font.Value)"
    Write-Host "Downloading $($font.Key)..."
    try {
        Invoke-WebRequest -Uri $url -OutFile $font.Key -UseBasicParsing
        Write-Host "  OK" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED: $_" -ForegroundColor Red
    }
}
Write-Host "Done! Restart the server to apply."
