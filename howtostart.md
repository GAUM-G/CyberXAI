-------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------

cd D:\honeypot_v2
n8n.cmd start

cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
$env:N8N_WEBHOOK_URL=""
python run.py

cd D:\honeypot_v2\website\backend
npm.cmd run dev

cd D:\honeypot_v2\website\frontend
npm.cmd run dev


cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1
python .\simulation\n8n.py --mode local

Username: admin' OR '1'='1 ; <script>alert('XSS')</script>
Password: test