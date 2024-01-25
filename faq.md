# Frequently asked questions

**What software can the updater.exe update?**

See the [list of supported applications](./supported_applications.md).

**Does the updater support 32 bit and 64 bit versions of applications?**

Yes.
If there are 32 bit and 64 bit versions of an application, the updater will
detect the installed version and will download and install the matching patch.

**Can the updater be used to install Microsoft patches that are usually
installed via Windows Update?**

No. There are no plans to change that either.

Most Microsoft software can be updated via the Windows Update function, so there
is no need to do that with another program. I know that Windows Update can be
painfully slow on older Windows versions like Windows Vista and Windows 7, but
that would be the same with any program that tries to automate that process
using the Windows Update API.

**Why does the updater not support application _X_ yet?**

Probably due to lack of time (and maybe interest) to implement it.

**Can you add application _X_ to the updater, so that I can use it to update
_X_?**

Maybe.

There are a couple of preconditions though:

* The application must be freely available over the internet.
* The developers / creators of the application must provide a public download
  for patches / updates to their software.
* Downloads of patches / updates must provide a checksum like SHA-512 or a
  similar checksum so that the integrity of the downloaded file can be verified
  before installing it.
* The installation parameters (especially for silent background installation)
  have to be documented somewhere where they can be found easily.

**Can I send you pull requests for an application that shall be added to the
updater?**

Sure. Just make sure you tested it before submission, because I will decline
any pull requests that do not compile or have similar issues.

**Do I need to update the updater.exe to make sure I get the latest software?**

No, not necessarily.

updater.exe has a builtin mechanism that can find the latest software versions
by checking the servers of the software creators / developers. This means that
the updater.exe can for example find updates for Firefox 123 when they are
available even if this version was not released when the updater.exe was
created.

However, when new applications are added to the updater.exe and you want to
use the updater to update that new application, you have to get the newer
version of updater.exe.

Nevertheless you should still strive to use the newest available version of
updater in order to get fixes and improvements and get the best update
experience that the updater can provide.
