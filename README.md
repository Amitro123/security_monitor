# Security Monitor — Daily Security Check

This script runs a daily security check to identify threats and suspicious behavior, including unknown background processes, automated startups, hidden remote connections, and settings that could indicate prompt injection or system takeover.

## Installation / Setup

1. Click **Start** and search for **PowerShell**.
2. Right-click → **"Run as administrator"**.
3. In the window that opens, run this unified setup command:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Path\To\Your\security_monitor\setup.ps1"
```

*(Make sure you replace `"C:\Path\To\Your\security_monitor\setup.ps1"` with the actual path to the cloned directory.)*

### Interactive Setup
The setup process is completely interactive!
During setup, you will be prompted to:
- **Enter a Gmail Address** to receive alerts (or you can press Enter to skip).
- **Enter a Gmail App Password** securely in the prompt.
- **Choose a Time** for the daily scheduled execution (e.g. `14:00`, or press Enter to keep `09:00`).

### Gmail App Password Requirement
Note: Google security prevents scripts from logging in with your normal password. During setup, you must use a **16-letter App Password**.
1. Go to [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Create a new app password named "Security Monitor".
3. Copy the 16-letter code (no spaces) provided by Google and paste it into the PowerShell prompt.

## Configuration & Safety

- The script creates auto-configuration in `config.json`.
- **Note:** The `config.json` stores your Gmail App Password in plain text. Do not commit this file to public repositories (a `.gitignore` is provided to keep it local). If using for personal local use, this is generally accepted, but keep it in mind.
- If you wish to disable email alerts, open `config.json` and change the app password to `YOUR_GMAIL_APP_PASSWORD_HERE`.

## Testing the Flow
To ensure that the Windows balloon notification and the email system work perfectly, you can run an instant "simulated threat" test. 

Open PowerShell in the folder where the app is located and run:
```powershell
python security_check.py --test
```
This will instantly pop a Windows notification alert and send you an email detailing a "fake_miner.exe", allowing you to confirm that the entire alert pipeline is correctly configured!

## Uninstallation

To remove the scheduled background task, open PowerShell (as Administrator) and run:
```powershell
Unregister-ScheduledTask -TaskName "DailySecurityMonitor" -Confirm:$false
```
Afterwards, you can safely delete the `security_monitor` folder.
