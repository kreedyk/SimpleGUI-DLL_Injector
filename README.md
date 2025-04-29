# K-Injector

K-Injector is a powerful command-line DLL injector that allows you to inject DLLs into running processes. This tool provides a streamlined command-line interface for quick and efficient DLL injection operations.

## Features

- List all running processes
- Process selection by name, PID, or index
- DLL selection by path or from recent DLLs list
- Architecture compatibility checking (32-bit vs 64-bit)
- Recent DLLs history
- Detailed injection status reporting

## Usage

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

List all running processes:
```
k-injector -l
```

List recent DLLs:
```
k-injector -r
```

Inject a DLL into a process by name:
```
k-injector -p notepad.exe -d C:\path\to\mydll.dll
```

Inject a DLL into a process by PID:
```
k-injector -p 1234 -d C:\path\to\mydll.dll
```

Inject a DLL into a process by index (after listing processes):
```
k-injector -i 5 -d C:\path\to\mydll.dll
```

Use a recently used DLL:
```
k-injector -p chrome.exe -rd 0
```

## Workflow Example

A typical workflow might look like this:

1. List all running processes to find the one you want to inject into:
   ```
   k-injector -l
   ```

2. Note the index of the target process (e.g., 42 for chrome.exe)

3. Inject your DLL:
   ```
   k-injector -i 42 -d C:\path\to\mydll.dll
   ```

4. For subsequent injections, you can use the recent DLLs feature:
   ```
   k-injector -i 42 -rd 0
   ```

## Important Notes

- The tool checks for architecture compatibility between the DLL and the target process. You cannot inject a 32-bit DLL into a 64-bit process or vice versa.
- The tool requires administrative privileges to inject into most processes.
- Recent DLLs are stored in `recent_dlls.txt` in the same directory as the executable.
- For the best experience, run K-Injector with administrative privileges.

## Troubleshooting

If you encounter issues:

1. Make sure you're running K-Injector as administrator
2. Verify that the DLL and target process have matching architectures (both 32-bit or both 64-bit)
3. Check that the DLL file exists and is accessible
4. Ensure the target process is still running
5. If the injection fails, try using the process ID instead of the process name