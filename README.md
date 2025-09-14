# IDA Enums Helper Plugin

![logo](logo.jpg)

The IDA Enums Helper Plugin is a tool designed to streamline enum management within IDA Pro. It introduces three key actions to enhance your workflow:

- **Rename Enum Member**: Quickly rename an enum member. *(Hotkey: N)*
- **Add Number to an Enum**: Add a new number to an existing or new enum. *(Hotkey: A)*
- **Add Number to the Last Used Enum**: Add a new number to the most recently used enum. *(Hotkey: Shift-A)*

These actions are also accessible via the context menu in the pseudocode view.

### Compatibility
- Tested with IDA Pro 9.2 on macOS.
- Expected to work on Windows and Linux as well.

### Known Issues
- **Cached Decompiled Code**: Changes made by renaming or adding enum members are not stored in the cached decompiled code. To view the updates, refresh the pseudocode view by pressing `F5`. This issue only occurs if you restart IDA and reopen the same file; otherwise, changes are visible immediately.
- **Enum Member Name Conflicts**: If you attempt to add a number that already exists in an enum with a different name, the plugin will not add it and will prompt you to choose a different name.
- **Enum Member Renaming in `switch` Statements**: Renaming enum members used in `switch` cases is not currently supported. This is a limitation of IDA Pro itself.

## Installation
To install the IDA Enums Helper Plugin, follow these steps:

1. Ensure that IDA Pro is installed on your system.
2. Clone or download this repository.
3. Copy the `enums_helper.py` file into the `plugins` directory of your IDA Pro installation.

For further assistance or to report issues, please refer to the repository's issue tracker.