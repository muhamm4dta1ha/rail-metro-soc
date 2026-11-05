"""Shared contracts for the Rail/Metro SOC project.

Everything that crosses a module boundary lives here: the event schema, the ground-truth
format, run ids and the lab address space. Changing this package is a *contract change*
(see CONTRIBUTING.md): it needs tests, an update of docs/contracts/ and approval from the
other modules.
"""

__version__ = "0.1.0"
CONTRACT_VERSION = "0.1"
