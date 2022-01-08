## python bindings

- https://infosecaddicts.com/python-and-metasploit/
- https://github.com/sqlmapproject/sqlmap
- https://github.com/nmmapper/python3-nmap
    - https://github.com/nmmapper/python3-nmap/blob/master/nmap3/nmapparser.py
- https://pypi.org/project/dirbpy/
- https://github.com/bostonlink/python-scripts
    - https://github.com/bostonlink/python-scripts/blob/master/exploit_db_search_v2.py
- https://pypi.org/project/python3-nmap/
- https://jmespath.readthedocs.io/en/latest/
- https://lxml.de/
    - https://lxml.de/element_classes.html
- https://devhints.io/xpath#axes-1
- https://stackoverflow.com/a/30964145
- https://json-schema.org/ we use this at work, when we write APIs we write schemata first and our dev scripts will
  convert these to Typescript types that we can reference wherever
- https://pythonrepo.com/repo/bahruzjabiyev-t-reqs-http-fuzzer-python-working-with-http
- https://sdet.us/form-fuzzing-python-mechanize/
- https://bahruz.me/papers/ccs2021treqs.pdf

## my own code/use libs

- parallel modules/dynamic priority -- we don't want to block or hog network IO on fruitless search paths (i.e. what if
  there's a fake login form that leads nowhere?)
- store data in database
    - serialize?
- http parser/redirect follower
    - HTML form detector
    - keyword detector
- http header analyzer
    - vhosts
    - redirects
    - subdirs
        - subdir fuzzer
- payload generation/mutator
- What are similarities between all the HTB challenges so far?
