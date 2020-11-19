## Revaultd blackbox tests

Here we test `revaultd` by starting it on a regression testing Bitcoin network,
and by then talking to it as an user would, from the outside.

Python scripts are used for the automation, and specifically the `pytest` framework
and its fixtures.

Credits: some (a lot) of the fixtures and utilities originated from the great
[C-lightning test framework](https://github.com/ElementsProject/lightning/tree/master/contrib/pyln-testing)
and adapted.

### How to run the tests

```
# Create a new virtual environment, preferably.
python3 -m venv venv
. venv/bin/activate
# Get the deps
pip install -r tests/requirements.txt
# Run the tests (you can pimp this line, and increase `-n` as the number of tests increase)
pytest -vvv -n 2 tests/
```
