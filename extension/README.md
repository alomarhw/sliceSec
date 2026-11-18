# sliceSec for VS Code

This folder holds the VS Code extension. See the [repository README](../README.md) for what it does and how to
install the analysis it runs.

## Commands

- *sliceSec: Analyze Workspace*
- *Forward Slice of Variable at Cursor*
- *Show Taint Path to Variable at Cursor*
- *Clear Highlights*
- *Restart Analysis Server*

## Settings

- `slicesec.pythonPath`
- `slicesec.backendPath`: the folder that contains the `slicesec` package. Leave it empty if you installed the
  package with pip.
- `slicesec.maxHops`
- `slicesec.analyzeOnSave`
