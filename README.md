# EnumerateAllKernelCallbacks
What? > </br>
List all registered "Process Creation" / "Load Image" / "Registry R/W" - Callbacks.</br>
And Iterate over all Object Types. If a Type supports Callbacks list all of its Procedures. Which lets you easily hook them.</br>
How? > </br>
By abusing the vulnerable dbutil_2_3.sys driver we get arbitrary read/write primitives in the kernel. </br>
This Project is free of hardcoded Offsets (x64). It will work on every Windows. </br>
As an extra the programm will also resolve the ETWTrace-Address. You can just flipp the bit at the given ETWStatus-Address to disable tracing.
[!alt text](https://github.com/Flerov/EAKC-EnumAllKernelCallbacks/blob/main/shot.png)
</br></br>

Have fun :) and make sure not to forget to load the driver first. Works also with manual mapping.
