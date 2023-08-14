# Malpacks
Tools to find malicious packages inside package manager (PyPI, npm, and Gem)

## Total malicious packages
* npm: 1823
* PyPI: 5985
* Gem: 725

## Installation
Simply clone the repository, install requirements and run the script

* $ git clone https://github.com/daffainfo/malpacks
* $ pip3 install -r requirements.txt
* $ python3 main.py

## Usage
Available options:
* `--all` option

To scan all the package managers (PyPI, npm, and Gem)

Example:
```bash
$ python3 main.py --all
```

* `--packages` option

Define package manager to test (PyPI, npm, and Gem)

Example:
```bash
$ python3 main.py --packages npm,pypi
```

## To-Do List
- [ ] Scan a file that contain list of packages
  - [ ] Scan requirements.txt (Python)
  - [ ] Scan package.json (npm)
- [ ] More output options
  - [ ] JSON
  - [ ] YAML
- [ ] Add more package manager
  - [x] PyPI
  - [x] npm
  - [x] Gem
  - [ ] Go
  - [ ] Composer
- [ ] Add more malicious packages
  - [x] https://blog.phylum.io/phylum-discovers-another-attack-on-pypi/
  - [x] https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems
  - [ ] https://github.com/DataDog/malicious-software-packages-dataset