# Description

This tool looks for either the processes that have a certain binary loaded or the processes that don't. This is useful in the following scenarios:

* It allows to detect processes where an specific EDR/AV dll is not loaded. This could lead to EDR's exception detection.
* It allows to obtain the PID of an specific process with a minimum cross process activity (e.g. looking for processes with c:\windows\sytem32\lsass.exe loaded will give us the Lsass' PID).
* It allows to obtain the PID of a service or a RPC/COM server withouth iterating over each running svchost process.

Maybe you can find other valuable ways to use this tools. These results are obtained avoiding to iterate over **all the processes in the system** and with a reduced noise.

The tool obtains all the processes where a certain binary is loaded by calling `NtQueryInformationFile` with the flag `FileProcessIdsUsingFileInformation`. Then and only if required, `EnumProcesses` is called to obtain all processes' PID, and finally both results are compared in order to obtain a final PID list. If the tool is not running on quiet mode, the final PIDs are translated into the process main module's fully qualified path.

If you want to reduce the cross process activity, use the **quiet** mode (`--quiet` or `-q`). In this case, no process handle will be opened, but the tool will only retrieve the PIDs and not the fully qualified paths.

The tool is fully compatible with Win10 and later and Windows Server 2016 and later. For older OS versions,the call to `OpenProcess` (line `src::main.rs:108`) requires `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ` instead of just `PROCESS_QUERY_LIMITED_INFORMATION` (or you can just stick to the quiet mode which doesn't open any process handle). 

# Compilation 

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\bin_finder\bin_finder> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and execute the tool:

	C:\Users\User\Desktop\Bin-Finder> cargo build --release
	C:\Users\User\Desktop\Bin-Finder\target\release> bin_finder.exe -h

# Usage 
Bin-finder has two different usage modes. The default mode will look for all the processes that don't have loaded the specified binary. For example, we can search for all the processes that do not have loaded the CrowdStrike dll:

![All processes without CS.](/images/find.png "All processes without CS.")

This is pretty useful when you are looking for directories/processes within the EDR's exception list.

If you want to reduce the cross process activity, it can be used the quiet mode to retrieve only the PIDs:

![All processes without CS.](/images/find_quiet.png "All processes without CS.")

Also, if you dont know the name or the path of the dll that you are looking for, you can try listing the modules loaded on a regular process using the flag `-l` or `--list` (this is also useful to spot whether or not there is an EDR in place):

![List modules.](/images/list.png "List modules.")

The second usage mode is the reverse lookup (flags `-r` or `--reverse`), which will look for all the processes that have currently loaded the specified binary. For example, maybe you are interested in getting the PID of the process that is running the StorSvc service. In that case, just make a reverse lookup for the dll that implements the RPC server used by that service:

![Reverse lookup.](/images/reverse.png "Reverse lookup.")

This reverse lookup can also be used to directly obtain a process' PID by specifying its main module's full path (usually an .exe file) without the need to iterate over all processes in the system. This is how you would obtain all running chrome.exe's PID:

![Exe reverse lookup.](/images/reverse_exe.png "Reverse lookup.")


# Credits

* [@ShitSecure](https://twitter.com/ShitSecure) for [this cool script](https://gist.github.com/S3cur3Th1sSh1t/d9aad93027aad893adae8805d59e2d73) that inspired me to create this tool.
