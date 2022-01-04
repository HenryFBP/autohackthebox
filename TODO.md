## python bindings

- https://infosecaddicts.com/python-and-metasploit/
- https://github.com/sqlmapproject/sqlmap
- https://github.com/nmmapper/python3-nmap
- https://pypi.org/project/dirbpy/
- https://github.com/bostonlink/python-scripts
    - https://github.com/bostonlink/python-scripts/blob/master/exploit_db_search_v2.py
- https://pypi.org/project/python3-nmap/
- https://jmespath.readthedocs.io/en/latest/
- https://lxml.de/
    - https://lxml.de/element_classes.html

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
