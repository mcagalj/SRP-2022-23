# **Sigurnost računala i podataka** <!-- omit in toc -->

## Lab 2: Python crash course
U okviru vježbe student će postaviti i testirati okruženje za pisanje i pokretanje Python skripti. Također će se upoznati s važnim konceptima Python jezika (relevantnim za laboratorijske vježbe) kao što su definicija funkcija, upravljanje modulima i paketima, rad sa stringovima i dr.

### Postavljanje razvojnog okruženja (VSCode Dev Containers)

U okviru laboratorijskih vježbi koristiti ćemo Visual Studio Code (VSC) za pisanje i pokretanje Python skripti. Pri tome ćemo koristiti Docker tehnologiju za kreiranje identičnog razvojnog okruženja na svim računalima.

1. Pokrenite Visual Studio Code i uvjerite se da imate instaliranu ekstenziju Dev Containers.
2. Uvjerite se da je na lokalnom računalu pokrenuta Docker Desktop aplikacija (npr. u Windows terminalu izvršite naredbu `docker` i uvjerite se da je ista prepoznata kao valjana).
3. Otvorite *View > Command Palette* izbornik i pokrenite **Dev Containers: Clone Repository in Named Container Volume…**
4. Unesite sljedeći GitHub URL u odgovarajuće polje i odaberite opciju **Clone git repository from URL**:
    ```bash
    https://github.com/mcagalj/srp-dev-container
    ```

5. U sljedećem izborniku, odaberite opciju **Create a new volume…** i unesite svoje ime (npr., `mario-cagalj`).
    > Na ovom virtualnom disku biti će pohranjene vaše skripte. Stoga je važno da ih nazovete jedinstvenim imenom kako bi na sljedećim vježbama mogli bez problema pronaći svoje skripte.

6. U sljedećem koraku trebate unijeti **target folder name**. Odaberite ponuđeno ime (`srp-dev-container`) i prihvatite pritiskom tipke Enter.
    > Pričekajte nekoliko trenutaka dok Visual Studio Code kreira odgovarajuće Docker okruženje u kojem ćete moći pokretati Python skripte.

7. Testirajte razvojno okruženje tako da otvorite Python skriptu `hello.py` koja se nalazi u direktoriju `01-hello`. Skriptu možete pokrenuti na više načina. U okviru labova, mi ćemo najčešće koristiti integriani terminal u VSC-u.  Otvorite novi terminal *Terminal > New Terminal*, uđite u direktorij `01-hello`:

    ```bash
    cd 01-hello
    ```

    Konačno, pokrenite Python skriptu `hello.py`:

    ```bash
    python hello.py
    ```

### Ponovno pokretanje i zaustavljanje razvojnog Docker okruženja

Kad dođete na sljedeći termin vježbi i želite ponovo otvoriti prethodno kreiran virtualni disk i Docker razvojno okruženje napravite sljedeće.

1. U Visual Studo Code-u, kliknite/odaberite izbornik **Remote Explorer**. U tom izborniku trebali bi vidjeti izlistane sve razvojne Doker kontejnere i razvojne virtualne diskove (*volumes*). Prelaskom mišem preko kontejnera trebali bi moći prepoznati “svoj” kontejner prema imenu virtualnog diska kojeg ste ranije kreirali (npr. `mario-cagalj`). Alternativno, desnim klikom na kontejner i odabirom opcije **Show Details** možete dobiti detaljniji uvid u taj Docker kontejner.
2. Kad ste pronašli odgovarajući Docker kontejner u **Remote Explorer**-u, desnim klikom na kontejner i odabirom opcije **Open Folder in Container** otvarate direktoriju u kojem ste ranije pisali svoje Python skripte.

    > Promjene koje ste ranije radili u ovom direktoriju trebale bi ostati sačuvane.

3. Ako želite zaustaviti Docker kontejner, najbolja opcija je **Close Remote Connection** (crveni botun u donjem lijevom kutu).

### Python osnove

#### Hello, World

```python
print("Hello, FESB!")

# This is a comment

'''
This a multiline comment.
Let us define a new variable "name".
'''
name = "FESB"

# Let's print something
print("Hello, {}".format(name))
print(f"Hello, {name}!")
```

#### Funkcije

1. Simple one

   ```python
   def hello(name):
       """ Say hello to name """
       print(f"Hello, {name}!")

   # Let us call the function
   hello("FESB")
   ```

2. Playing with arguments

   ```python
   def say(**args):
       """ Function with keyword arguments (kwargs) """
       what = args.get('what', 'Hello')
       name = args.get('name', 'Nobody')
       print(f"{what}, {name}!")

   # Let us test the function
   say(what="Hello", name="FESB")
   say(what="Hi", name="FESB")
   say(name="FESB", what="Hi")
   say(name="FESB")
   say(what="Hi")
   say()

   # ** unpacks dictionaries
   my_dicionary = {'what': 'Hi', 'name': 'FESB'}
   say(**my_dicionary)
   ```

3. Return something

   ```python
   def encrypt(plaintext, **params):
       key = params.get('key')
       assert key, 'Encryption key is missing'

       mode = params.get('mode')
       assert mode, 'Encryption mode is missing'

       cipher = Cipher(CIPHER(key), mode, backend=default_backend())
       encryptor = cipher.encryptor()
       ciphertext = encryptor.update(plaintext)
       ciphertext += encryptor.finalize()

       return ciphertext
   ```

### Python moduli

#### Kreiranje jednostavnog modula

Pohranimo prethodne funkcije u datoteku `speak.py`:

```python
# File "speak.py"
def hello(name):
    """ Function hello """
    ...

def say(**args):
    """ Function say """
    ...

# Constant
DEFAULT_NAME = "FESB"
```

Kreirajmo novu datoteku `speak_FESB.py` (u istom direktoriju kao i `speak.py`):

```python
# File "speak_FESB.py"
# Import functions from module "speak"
import speak

# Let's test the imported functions
speak.hello("FESB")
speak.say(name="FESB")
```

```python
# File "speak_FESB.py"
# Here we import only one function
from speak import say

say(name="FESB")
```

```python
# File "speak_FESB.py"
# We can even rename an imported function
from speak import say as reci

reci(name="FESB")
```

```python
# File "speak_FESB.py"
# Importing a constant
from speak import DEFAULT_NAME
from speak import say
'''
Alternatively we can do the following:
    from speak import say, DEFAULT_NAME
or
    from speak import (
        say,
        DEFAULT_NAME
    )

'''

say(name=DEFAULT_NAME)
```

#### _Optional:_ Moduli kao Python skripte

**Što predstavlja uvjet `if __name__ == '__main__':` kojeg često nalazimo u Python modulima?**

U prethodnom primjeru kreirali smo modul `speak` s ciljem korištenja istog unutar drugih Python skripti. Python moduli su zapravo samo obične Python skripte pa ih kao takve možemo i izravno pozivati/izvršavati (ne moramo ih nužno uvoditi u posebnu skriptu - `import speak`). Dakle, pozivanje modula kao skripte kako je prikazano u nastavku sasvim je legitimno u Pythonu.

```shell
python speak.py
```

Često u modulima možemo naći sljedeći kondicionalni izraz: `if __name__ == '__main__':`. U nastavku ćemo objasniti značenje istog. Definirajmo modul `speak` kako slijedi:

```python
# File "speak.py"
def hello(name="FESB"):
    """ Say hello to name (defaults to FESB) """
    print(f"Hello, {name}!")

# This function is executed in all cases
hello(__name__)


if __name__ == '__main__':
    # This part is executed only if the script
    # is called directly (i.e., python speak.py)
    hello(__name__)
    hello()
```

Kada modul koristite izravno kao samostalnu skriptu, odnosno kada ga pozivate kao `python speak.py`, Python interpreter postavlja specijalnu varijablu `__name__` u vrijednost `__main__`. S druge strane, kada isti modul uvozite u drugu skriptu, vrijednost varijable `__name__` postaje ime tog modula. Na ovaj način znate je li modul korište izravno ili je uvezen u drugu skriptu i shodno tome možete izvršiti ili ne izvršiti odgovarajuću logiku. Ovo je npr. korisno kada radite testove za modul. Testove naravno ne želite izvršavati prilikom korištenja modula unutar drugih skripti.

Usporedite rezultate izvršavanja Python skripti u nastavku.

1. Izravan poziv modula

   ```shell
   python speak.py
   ```

2. Posredno korištenje modula (`import <module_name>`)

   ```python
   # File "speak_FESB.py"
   # Import "hello" function from module "speak"
   from speak import hello

   # Use hello function
   hello("FESB")
   ```

   ```shell
   python speak_FESB.py
   ```

### Python packages

Python paketi (eng. _package_) služe za grupiranje i strukturiranje više povezanih modula u jednu cjelinu. U osnovi, Python paket je skup datoteka pohranjenih i organiziranih u zajednički direktorij. Standardna Python-ova biblioteka ([_The Python Standard Library_](https://docs.python.org/3/library/)) uključuje brojne korisne module i pakete koji su pisani u C ili Python jeziku.

Module i pakete koji nisu dio standardne biblioteke možete instalirati pomoću odgovarajućih upravitelja paketima. Popularan alat za instalaciju Python paketa je `pip`, a popularan repozitorij s Python paketima je [Python Package Index (PyPI)](https://pypi.org/).

#### Package manager `pip`

U okviru laboratorijskih vježbi, za potrebe rada s kriptografskim primitivima (enkripcijskim algoritmima, kriptografskim _hash_ funkcijama, i dr.) koristiti ćemo Python paket [`cryptography`](https://pypi.org/project/cryptography/).

Tragom toga, pokušajte izvršiti sljedeću Python skriptu unutar vlastitog virtualnog okruženja; ne zamarajte se za sada činjenicom da ne znate čemu služe moduli koje uvozimo u skriptu:

```python
# File package_test.py

from cryptography.fernet import Fernet
'''
Importing the class "Fernet" from the package "cryptography",
the subpackage "fernet"; recall, (sub)packages are just ordinary
folders. You can easily verify this by looking here:
https://github.com/pyca/cryptography/tree/master/src

And yes, Python has classes and supports object-oriented
programming.
'''

# Let us now use the imported class Fernet
key = Fernet.generate_key()
f = Fernet(key)
ciphertext = f.encrypt(b"A really secret message. Not for prying eyes.")

print(f"\nCiphertext: {ciphertext}")
```

```shell
python package_test.py
Traceback (most recent call last):
  File "crypto.py", line 1, in <module>
    from cryptography.fernet import Fernet
ModuleNotFoundError: No module named 'cryptography'
```

Očigledno nemamo instaliran traženi paket `cryptography` na lokalnom računalu. Preciznije, željeni paket nije instaliran u našem virtualnom okruženju `(mcagalj)`. To možemo napraviti korištenjem alata **`pip`** kako je prikazano u nastavku:

```shell
pip install cryptography
```

Za više informacija o instaliranom paketu izvršite naredbu `pip show <ime_paketa>`. Pokušajmo ponovo izvršiti našu skriptu. Voila!

```shell
python package_test.py

Ciphertext: b'gAAAAABbtx7LWMixhxgjbpcPF7KOszxbfLuK1lwLg1PYTizsrHnCI2B8NluKaHos5WsUkKfOyjWaD80ogmBlSI8kYjo8edlyGz5wn6fin1QpirGLBDSEVSpzecqfdPCS1PgF-KHME4H3'
```

#### The Requirements file

Zamislite situaciju u kojoj u projektu koristite više vanjskih modula koje ste pojedinačno instalirali (`pip install module_A`, `pip install module_B`, ...). Želite svoj projekt poslati prijatelju koji nema instalirane potrebne module te ih treba instalirati. Ako vaš projekt koristi veliki broj paketa/modula (> 10), pojedinačna instalacija istih biti će jako destimulirajuća za vašeg prijatelja.

Upravitelj paketima **`pip`** ima rješenje za ovakve situacije. `pip` omogućava instalaciju paketa navedenih u odgovarajućoj datoteci (tzv., _requirements file_). Pretpostavite da su vaši moduli navedeni u datoteci `requirements.txt`. Izvršavanjem sljedeće naredbe pokrećete instalaciju svih potrebnih modula.

```shell
pip install -r requirements.txt
```

Ostaje pitanje kako kreirati `requirements` datoteku. `pip` ima podršku i za ovu zadaću.
Ako želite samo izlistati module/pakete koje koristite u vašem projektu izvršite:

```shell
pip freeze
```

Ako iste želite pohraniti u npr. datoteku `requirements.txt`, izvršite:

```shell
pip freeze > requirements.txt
```

_That's it for now!_
