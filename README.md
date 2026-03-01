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

venv might cause issues so make sure you're on its environment first:

`source .venv/bin/activate` on Linux, `call venv\Scripts\activate` on Windows.

And then `ùvicorn app.main:app --reload` from bitguard-src.

Alternatively, you can use the Releases binaries, run them to start the API, and then run the Vault pswd manager on port 3000 with:

`python3 -m http.server 3000`

If the installer doesn't work for you, you can also use Pyinstaller to compile your own binaries, from the app directory.

## Inspiration
Nos hemos inspirado en algunas aplicaciones cotidianas, que usamos en nuestro día a día, tanto para generar contraseñas como para guardarlas en un gestor, para poder llevar a cabo el reto propuesto por Gradiant.
## What it does
Nuestro proyecto permite generar contraseñas robustas, además de comprobar si estas han sido expuestas a filtraciones. También permite guardar las contraseñas de manera segura.
## How we built it
Creamos una API con FastAPI, y las contraseñas se guardan de manera segura con un sistema de encriptación que consta de una clave privada y pública.  
## Challenges we ran into
Tuvimos que aprender a crear y usar una API, ya que nunca nos habíamos enfrentado a ello.
## Accomplishments that we're proud of
Estamos orgullosos de como ha quedado el proyecto en general, pero sobretodo, del diseño gráfico de este.
## What we learned
Hemos aprendido a realizar una extensión en Chrome, algo totalmente para nosotros.
## What's next for BitGuard
Nuestra intención es seguir aprendiendo, disfrutando con nuestros amigos y programando cada vez mejor para lograr obtener los mejores resultados.



