# Updater

Updater _(working title, final name may change)_ is a command line application
that can update popular third party software on Windows operating systems
easily.

Among the supported applications are Mozilla Firefox, Node.js LTS, 7-Zip,
LibreOffice, just to name a few. A complete list of applications that can
currently be updated with this application is available
[here](./supported_applications.md).

## Build status

[![GitHub CI](https://github.com/striezel/updater/workflows/.NET%20on%20Ubuntu/badge.svg)](https://github.com/striezel/updater/actions)
[![GitHub CI](https://github.com/striezel/updater/workflows/MSBuild%20on%20Windows/badge.svg)](https://github.com/striezel/updater/actions)
[![GitLab pipeline status](https://gitlab.com/striezel/updater/badges/master/pipeline.svg)](https://gitlab.com/striezel/updater/)

## Prerequisites

To run the `updater` program you need the .NET 8 runtime.
The current .NET 8 runtime can be downloaded from
<https://dotnet.microsoft.com/en-us/download/dotnet/8.0/runtime>.

## Usage

The updater is a command-line program, there is no graphical user interface yet
(and maybe there never will be one). Basic invocation is as follows:

    updater.exe operation [options]

### Operations
Operations or commands define the main action of the program. Only one of
these may be specified. Valid operations are:

* **check** - Displays which installed software can be updated, but does not
  actually perform the updates. This will display something like

  ```
  +-------------------------------------+--------+--------------+--------------+---------+
  | Software                            | type   | current      | newest       | can be  |
  |                                     |        | version      | version      | updated |
  +-------------------------------------+--------+--------------+--------------+---------+
  | Acrobat Reader 2020                 | 32 bit | 20.005.30407 | 20.005.30407 | no      |
  | CMake                               | 64 bit | 3.24.3       | 3.24.3       | no      |
  | Eclipse Temurin JDK 17 with Hotspot | 64 bit | 17.0.5.8     | 17.0.5.8     | no      |
  | Mozilla Firefox ESR (de)            | 64 bit | 102.4.0      | 102.4.0      | no      |
  | FileZilla FTP Client                | 64 bit | 3.62.0       | 3.62.0       | no      |
  | Git                                 | 64 bit | 2.38.1       | 2.38.1       | no      |
  | HeidiSQL                            | 64 bit | 12.1         | 12.1.0.6537  | no      |
  | KeePass                             | 32 bit | 2.52         | 2.52         | no      |
  | LibreOffice                         | 64 bit | 7.4.2.3      | 7.4.2.3      | no      |
  | MariaDB Server 10.5                 | 64 bit | 10.5.17.0    | 10.5.18      | yes     |
  | Node.js                             | 64 bit | 18.12.1      | 18.12.1      | no      |
  | Notepad++                           | 32 bit | 8.4.6        | 8.4.7        | yes     |
  | Pidgin                              | 32 bit | 2.14.10      | 2.14.10      | no      |
  | PuTTY                               | 64 bit | 0.78.0.0     | 0.78         | no      |
  | 7-Zip                               | 64 bit | 22.01        | 22.01        | no      |
  | TeamSpeak Client                    | 64 bit | 3.5.6        | 3.5.6        | no      |
  | TeamViewer                          | 64 bit | 15.35.7      | 15.35.7      | no      |
  | Mozilla Thunderbird (de)            | 64 bit | 102.4.2      | 102.4.2      | no      |
  | VLC media player                    | 64 bit | 3.0.17.4     | 3.0.17.4     | no      |
  | WinSCP                              | 32 bit | 5.21.5       | 5.21.5       | no      |
  +-------------------------------------+--------+--------------+--------------+---------+
  ```

* **update** - Updates every software that can be updated, i.e. downloads and
               installs new versions / updates. Possible output could be:

  ```
  2022-11-08 19:12:44 - Downloading https://downloads.mariadb.org/rest-api/mariadb/10.5.18/mariadb-10.5.18-winx64.msi...
  2022-11-08 19:13:10 - Calculating checksum of C:\Users\admin\AppData\Roaming\.updaterCache\mariadb-10.5.18-winx64.msi ...
  2022-11-08 19:13:11 - Info: Checksum of C:\Users\admin\AppData\Roaming\.updaterCache\mariadb-10.5.18-winx64.msi is correct.
  2022-11-08 19:13:11 - Verifying signature of C:\Users\admin\AppData\Roaming\.updaterCache\mariadb-10.5.18-winx64.msi ...
  2022-11-08 19:13:11 - Info: Signature and publisher of C:\Users\admin\AppData\Roaming\.updaterCache\mariadb-10.5.18-winx64.msi are correct.
  2022-11-08 19:13:11 - Info: Starting update of MariaDB Server 10.5...
  2022-11-08 19:13:28 - Info: Update process exited after 17 second(s) with code 0.
  2022-11-08 19:13:28 - Info: Update of MariaDB Server 10.5 was successful.
  2022-11-08 19:13:28 - Downloading https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.4.7/npp.8.4.7.Installer.exe...
  2022-11-08 19:13:30 - Calculating checksum of C:\Users\admin\AppData\Roaming\.updaterCache\npp.8.4.7.Installer.exe ...
  2022-11-08 19:13:30 - Info: Checksum of C:\Users\admin\AppData\Roaming\.updaterCache\npp.8.4.7.Installer.exe is correct.
  2022-11-08 19:13:30 - Verifying signature of C:\Users\admin\AppData\Roaming\.updaterCache\npp.8.4.7.Installer.exe ...
  2022-11-08 19:13:31 - Info: Signature and publisher of C:\Users\admin\AppData\Roaming\.updaterCache\npp.8.4.7.Installer.exe are correct.
  2022-11-08 19:13:31 - Info: Starting update of Notepad++...
  2022-11-08 19:13:34 - Info: Update process exited after 3 second(s) with code 0.
  2022-11-08 19:13:34 - Info: Update of Notepad++ was successful.
  2022-11-08 19:13:34 - 2 applications were updated.
  ```

* **help** - Shows a help message.
* **version** - Shows the version of the program.
* **license** - Shows license information for the program.
* **list-id** - Prints a list of software IDs to the standard output. These IDs
                can be used to exclude certain software from updates. See the
                option `--exclude` below for more information.

### Options
Options can change behaviour of the update process. Available options are:

    --auto-get-newer | --newer | -n
        Automatically tries to get information about newer versions of the soft-
        ware from the internet. The updater has a list of known newest software
        versions, but that information can get outdated quickly. That is why
        this option exists - it helps to get the latest software version.
        The option is enabled by default.
    --no-auto-get-newer | --no-newer | -nn
        Do not try to get information about newer software versions. It is not
        recommended to use this option, because it might mean that you get some
        slightly outdated updates.
    --timeout SECONDS | -t SECONDS
        Sets the timeout in seconds for a single update process. If an update
        runs longer than the specified amount of seconds, it gets cancelled. The
        default timeout is 1800 seconds.
    --exclude ID | --except ID | -e ID
        Excludes the software with the given ID from the update process. To get
        the ID for a specific software, run the program with the list-id
        option which lists all software IDs. You can use this option several
        times to exclude more than one software from the update process.
    --show-progress | --progress | -p
        Shows the download progress while downloading the updates. This is only
        relevant when the update operation was specified, it has no effect on
        other operations. Note that this can cause a very noisy output during
        downloads, because the progress may be updated several times per second.
    --pdf24-autoupdate
        Enable automatic updates for PDF24 Creator after update. This option is
        enabled by default.
    --no-pdf24-autoupdate
        Disable automatic updates for PDF24 Creator after update. This option is
        disabled by default.
    --pdf24-icons
        Enable desktop icons for PDF24 Creator during update. This option is
        enabled by default.
    --no-pdf24-icons
        Disable desktop icons for PDF24 Creator during update. This option is
        disabled by default.
    --pdf24-fax-printer
        Installs the fax printer for PDF24 Creator during update. This option is
        enabled by default.
    --no-pdf24-fax-printer
        Does not install the fax printer for PDF24 Creator during update. This
        option is disabled by default.

### Examples

Here are a few examples to give you a general idea:

* Check which software can be updated:

  `updater.exe check`

* Download and apply all available updates:

  `updater.exe update`

* Download and apply all available updates, but do not update Thunderbird and
  GIMP:

  `updater.exe update --exclude thunderbird --exclude gimp`

* Download and apply all available updates, but set timeout to 20 minutes (i.e.
  1200 seconds):

  `updater.exe update --timeout 1200`

## Frequently asked questions

If you have a question about the updater, please take a look at the
[FAQ](./faq.md) first.

## Getting the source code and building the application

Get the source directly from GitHub by cloning the Git repository (e.g. in Git
Bash) and change to the directory after the repository is completely cloned:

    git clone https://github.com/striezel/updater.git updater
    cd updater

That's it, you should now have the current source code of updater on your
machine.

After that, open Visual Studio (2019 Community Edition or later recommended)
and just build the solution **updater/updater.sln** from the checked out
sources.

## Version history

A changelog is available in [changelog.md](./changelog.md).

## Copyright and Licensing

Copyright 2016 - 2025  Dirk Stolle

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
