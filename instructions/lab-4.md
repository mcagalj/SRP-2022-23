# **Sigurnost računala i podataka** <!-- omit in toc -->

- [Lab 4: Message authentication and integrity](#lab-4-message-authentication-and-integrity)
  - [Message Authentication Code (MAC)](#message-authentication-code-mac)
    - [Zadatak 1](#zadatak-1)
    - [Zadatak 2](#zadatak-2)
      - [Kako preuzeti izazove sa servera?](#kako-preuzeti-izazove-sa-servera)
      - [Za provjeru MAC-a treba mi korištena tajna/ključ, gdje ću je naći?](#za-provjeru-mac-a-treba-mi-korištena-tajnaključ-gdje-ću-je-naći)
      - [Ali ne želim raditi manualno provjeru svih transakcija](#ali-ne-želim-raditi-manualno-provjeru-svih-transakcija)
      - [Automatsko izvlačenje _timestamp_-a i sortiranje po istom](#automatsko-izvlačenje-timestamp-a-i-sortiranje-po-istom)
  - [Digital signatures using public-key cryptography](#digital-signatures-using-public-key-cryptography)
    - [Zadatak 3](#zadatak-3)
      - [Kako učitati javni ključ iz datoteke?](#kako-učitati-javni-ključ-iz-datoteke)
      - [Kako provjeriti ispravnost digitalnog potpisa?](#kako-provjeriti-ispravnost-digitalnog-potpisa)


## Lab 4: Message authentication and integrity

Cilj vježbe je primjeniti teoretske spoznaje o osnovnim kritografskim mehanizmima za autentikaciju i zaštitu integriteta poruka u praktičnom primjerima. Pri tome ćemo koristiti simetrične i asimetrične kriptografske mehanizme: _message authentication code (MAC)_ zasnovane na simetričnim ključevima i _digitalne potpise_ zasnovane na javnim ključevima.

### Message Authentication Code (MAC)

#### Zadatak 1

Implementirati zaštitu integriteta sadržaja poruke primjenom odgovarajućeg _message authentication code (MAC)_ algoritma. Koristite pri tome HMAC mehanizam iz Python biblioteka [`cryptography`](https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/).

1. U lokalnom direktoriju kreirajte tekstualnu datoteku odgovarajućeg sadržaja čiji integritet želite zaštititi.

2. Učitavanje sadržaja datoteke u memoriju.

    ```python
    # Reading from a file
    with open(filename, "rb") as file:
        content = file.read()   
    ```

3. Funkcija za izračun MAC vrijednosti za danu poruku.

    ```python
    from cryptography.hazmat.primitives import hashes, hmac

    def generate_MAC(key, message):
        if not isinstance(message, bytes):
            message = message.encode()

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        signature = h.finalize()
        return signature
    ```

4. Funkcija za provjeru validnosti MAC-a za danu poruku.

    ```python
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.exceptions import InvalidSignature
    

    def verify_MAC(key, signature, message):
        if not isinstance(message, bytes):
            message = message.encode()
    
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        try:
            h.verify(signature)
        except InvalidSignature:
            return False
        else:
            return True
    ```

5. Pokušajte modificirati sadržaj datoteke i/ili potpis (odnosno MAC vrijednost) i uvjerite se da MAC algoritam uspješno detektira takve promjene.

#### Zadatak 2

**Utvrditi vremenski ispravnu/autentičnu skevencu transakcija (ispravan redosljed transakcija) dionicama**. Autenticirani nalozi transakcija (primjenom MAC-a) nalaze se na lokalnom poslužitelju:

[http://challenges.local](http://challenges.local)

**NAPOMENA:** Da bi pristupili serveru **trebate** biti dio lokalne mreže. Ako ni u tom slučaju niste u mogućnosti povezati se na server moguće je da server nije pokrenut, pa upozorite profesora.

Sa servera preuzmite personalizirane izazove (`challenges/<id_grupe>/<prezime_ime>/mac_challenge`). Nalozi za transakcije nalaze se u datotekama označenim kao `order_<n>.txt` a odgovarajući autentikacijski kod (_MAC tag_) u datotekama `order_<n>.sig`.

U nastavku su dane neke smjernice za jednostavnije rješavanje izazova.

##### Kako preuzeti izazove sa servera?

1. Preuzmite program `wget` dostupan na [wget download](https://eternallybored.org/misc/wget/).

2. Pohranite ga u direktorij gdje ćete pisati Python skriptu rješavanje ovog izazova.

3. Osobne izazove preuzimate izvršavanjem sljedeće naredbe u terminalu:

   ```console
   wget.exe -r -nH -np --reject "index.html*" http://challenges.local/challenges/<id_grupe>/<prezime_ime>/mac_challenge/
   ```

   >NAPOMENA: Ne zaboravite prilagoditi `<id_grupe>` i `<prezime_ime>`.  

##### Za provjeru MAC-a treba mi korištena tajna/ključ, gdje ću je naći?

Tajna vrijednost koja se koristi kao ključ u MAC algoritmu dobivena je iz vašeg imena (ne pretjerano siguran pristup):

```python
key = "<prezime_ime>".encode()
```

##### Ali ne želim raditi manualno provjeru svih transakcija

_Fair enough_, koristite nekakvu petlju:

```python

for ctr in range(1, 11):
    msg_filename = f"order_{ctr}.txt"
    sig_filename = f"order_{ctr}.sig"    
    print(msg_filename)
    print(sig_filename)
    ...
    is_authentic = ...

    print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

##### Automatsko izvlačenje _timestamp_-a i sortiranje po istom

Možete pohranite sve autentične poruke u odgovarajući niz, npr., `messages`, a zatim nad istim pozovite `sort` funkciju s _čudovišnim_ argumentom:

```pyhton
messages.sort(key=lambda m: datetime.datetime.fromisoformat(re.findall(r'\(.*?\)', m)[0][1:-1]))
```

>NAPOMENA: Ne zaboravite uključiti (`import`) Python module za upravljanje datumima (`datetime`) i regularnim izrazima (`re`).

### Digital signatures using public-key cryptography

#### Zadatak 3

Odrediti autentičnu sliku (između dvije ponuđene) koju je profesor potpisao svojim privatnim ključem. Odgovarajući javni ključ dostupan je na gore navedenom serveru. 

Slike i odgovarajući digitalni potpisi nalaze se u direktoriju `challenges/<id_grupe>/<prezime_ime>/public_key_challenge`. Za rješavanje ovog izazova koristite Python biblioteku [`cryptography`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/).

##### Kako učitati javni ključ iz datoteke?

I kako ga _deserijalzirati_ (što god to značilo).

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY
```

##### Kako provjeriti ispravnost digitalnog potpisa?

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True
```
