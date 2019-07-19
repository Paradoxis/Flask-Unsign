---
name: Something not working as it should?
about: Let's get that sorted out shall we? ✨
title: ''
labels: bug
assignees: Paradoxis

---

# What went wrong?
Did the program crash? Did it not crack the password (which you're 100% sure is right)? Does it freeze? Describe what you expected to happen and actually happened instead.

A good example of what to put here:

> I ran flask-unsign on this file and got a `ZeroDivisionError: division by zero` error, where it should have cracked it with the password `"password"`

Bad example:

> Fuck you your code doesn't work for shit

## Stack Trace
If you got a stack trace, please paste it here:

```
...
```

## To Reproduce
Please add the following files / info:

- The session cookie you wish to crack (or one which can reproduce the issue)
- The password file you're using (unless it's the built-in wordlist)
- The password you know the session is signed with

## System information
Please add the output of the following commands:

### Flask-Unsign Version
```
$  pip3 freeze | grep -i flask-unsign
...
```

### Flask-Unsign Type
```
$ file $(which flask-unsign)
...
```

### Python Version
```
$ python3 --version
...
```

### System Version
```
$ uname -a
...

$ cat /etc/issue
...
```

## Screenshots
A picture tells a thousand words, feel free to add one here if you have it

## Other stuff
Got any other info I should know about? Have a monkeypatch or proposed fix?  <br>
Feel like ranting about something? Feel free to do it here. Compliments are also welcome ✨
