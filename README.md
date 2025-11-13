# REshare IDA

IDAPython scripts to use the [REshare](https://github.com/v-p-b/reshare) reverse-engineering exchange format in IDA. 

## Installation

Install the project dependencies in the virtual environment of your choice:

```
reshare-ida/ $ python3 -m venv venv
reshre-dia/ $ source venv/bin/activate
(venv) reshare-ida/ $ pip install .
```

(uv and other project managers should also work)

## Usage 

### Import 

1. Edit the configuration constants at the top of `reshare-ida-import.py` according to your needs.
2. Start IDA from the shell with the activated virtual environment where dependencies are installed.
3. Execute the script (`File->Script file...` or Alt+F7)




