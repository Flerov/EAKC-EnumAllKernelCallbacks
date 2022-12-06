# DisableEdrAndKernelCallbacks
Disable Edr by flipping _TRACE_ENABLE_INFO Bit and all active Kernel Callbacks by modifying undocumented _CALLBACKS_LIST_ENTRY </br></br>

Reused Code from these Projects: (big Thanks you made everything alot easier to understand / apply) </br>
https://github.com/mzakocs/CVE-2021-21551-POC </br>
https://github.com/wavestone-cdt/EDRSandblast </br>
The FindDriver - Function is also reused code but I couldn't find the project, I will add when I can remember :) </br></br>

We will iterate over all _OBJECT_TYPES and look at the CallbacksList, since it is just a demonstration the code will only take one _CALLBACKS_LIST_ENTRY but this should be no problem for you to enhance the code to iterate through the whole _LIST_ENTRY struct ;) </br>
When we see that the Callback ist active, we disable it.
We will also disable EDR by flipping _TRACE_ENABLE_INFO bit to 0x0. </br></br>

Have fun :)
Maybe it will help you or you have ideas to improve this let me know!
I will try to add WinDbg Pictures to assist those who want to learn...
