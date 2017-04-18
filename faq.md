# Frequently asked questions

**What software can the updater.exe update?**

See the [list of supported applications](./supported_applications.md).

**Does the updater support 32 bit and 64 bit versions of applications?**

Yes.
If there are 32 bit and 64 bit versions of an application, the update will
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
any pull requests that do not compile or do not work.
