# BitGuard API
 
Backend service for BitGuard password vault.
This API handles encrypted vault entries, secure storage, and communication with the browser extension.

BitGuard API is responsible for:
  -Receiving vault entries from the browser extension
  -Encrypting sensitive data
  -Storing encrypted entries in the database
  -Generate new passwords


Providing secure access to stored credentials
Use a Python virtual environment for dependencies.
Run setup.bat to create and populate itguard-src\\venv (includes FastAPI + uvicorn).
You can install equests or other packages in the activated venv with pip install requests or add them to 
equirements.txt.

After activating, start the API:

`
cd bitguard-src
call venv\\Scripts\\activate
python main.py
`

