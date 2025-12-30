# REshare IDA

IDAPython scripts to use the [REshare](https://github.com/v-p-b/reshare) reverse-engineering exchange format in IDA. 

## Installation

Install the project dependencies in the virtual environment of your choice:

```
reshare-ida/ $ python3 -m venv venv
reshare-dia/ $ source venv/bin/activate
(venv) reshare-ida/ $ pip install .
```

(uv and other project managers should also work)

## Usage 

1. Edit the configuration constants at the top of `reshare-ida-{import,export}.py` according to your needs.
2. Start IDA from the shell with the activated virtual environment where dependencies are installed.
3. Execute the script (`File->Script file...` or Alt+F7)

### Configuration

#### Common

* `LOG_FILE` - Path to the log file (`None` disables file logging)
* `LOG_LEVEL` - Log level constant for the `logging` module

#### Exporter 

* `EXPORT_PATH` - Path to the export JSON

#### Importer

* `IMPORT_PATH` - Path to the REshare JSON file to import
* `FUNC_SYM_IMPORT_ALLOW_RE` - Only import function signatures that match this regular expression (`None` to disable).
* `FUNC_SYM_IMPORT_DENY_RE` - Don't import function signatures that match this regular expression (`None` to disable).
* `TYPE_IMPORT_ALLOW_RE` - Only import types that match this regular expression (`None` to disable). 
* `TYPE_IMPORT_DENY_RE` - Don't import types that match this regular expression (`None` to disable).


