# K-Injector

K-Injector is a powerful command-line DLL injector that allows you to inject DLLs into running processes. This tool provides a streamlined command-line interface for quick and efficient DLL injection operations.

## Features

- List all running processes
- Process selection by name, PID, or index
- DLL selection by path or from recent DLLs list
- Architecture compatibility checking (32-bit vs 64-bit)
- Recent DLLs history
- Detailed injection status reporting

## Usage (CLI Version)

```
k-injector [options]
```

### Options

- `-h, --help`: Show help message
- `-l, --list`: List all running processes
- `-r, --recent`: List recent DLLs
- `-p, --process <pid/name>`: Select process by PID or name
- `-d, --dll <path>`: Select DLL by path
- `-i, --index <idx>`: Select process by index from list
- `-rd, --recent-dll <idx>`: Select DLL by index from recent list

### Examples

```bash
k-injector -l                          # List processes
k-injector -p notepad.exe -d mydll.dll # Inject into process by name
k-injector -i 5 -rd 0                  # Inject recent DLL by index
```

## Prefer a GUI?

If you want a user-friendly graphical interface, try the GUI version here:  
👉 [Simple GUI DLL Injector](https://github.com/kreedyk/simpleGUI-dll-injector/tree/gui)

Same functionality, but easier to use visually.

## Workflow Example

1. List all running processes:
   ```
   k-injector -l
   ```
2. Note the index of your target process (e.g., 42)
3. Inject your DLL:
   ```
   k-injector -i 42 -d C:\path\to\mydll.dll
   ```
4. Use a recent DLL next time:
   ```
   k-injector -i 42 -rd 0
   ```

## Important Notes

- You must match architecture (32-bit or 64-bit) between DLL and target process.
- Requires administrator privileges for most processes.
- Recent DLLs stored in `recent_dlls.txt` (in same folder as the executable).
- Always run as administrator for best compatibility.

## Troubleshooting

1. Run as administrator
2. Check architecture match
3. Confirm DLL file exists and is accessible
4. Make sure the target process is running
5. Try PID instead of process name if injection fails
