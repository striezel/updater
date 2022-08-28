# Updater

Updater _(working title, final name may change)_ is a command line application
that can update popular third party software on Windows operating systems
easily.

Among the supported applications are Mozilla Firefox, Node.js LTS, 7-Zip,
LibreOffice, just to name a few. A complete list of applications that can
currently be updated with this application is available
[here](./supported_applications.md).

## Build status

* GitHub Actions:
[![GitHub CI](https://github.com/striezel/updater/workflows/.NET%20on%20Ubuntu/badge.svg)](https://github.com/striezel/updater/actions)
[![GitHub CI](https://github.com/striezel/updater/workflows/MSBuild%20on%20Windows/badge.svg)](https://github.com/striezel/updater/actions)
* GitLab CI:
[![GitLab pipeline status](https://gitlab.com/striezel/updater/badges/master/pipeline.svg)](https://gitlab.com/striezel/updater/)

## Prerequisites

To run the `updater` program you need the .NET 6 runtime.
The current .NET 6 runtime can be downloaded from
<https://dotnet.microsoft.com/en-us/download/dotnet/6.0/runtime>.

## Usage

The updater is a command-line program, there is no graphical user interface yet
(and maybe there never will be one). Basic invocation is as follows:

    updater.exe operation [options]

### Operations
Operations or commands define the main action of the program. Only one of
these may be specified. Valid operations are:

* **check** - displays which installed software can be updated, but does not
              actually perform the updates.
* **update** - updates every software that can be updated, i.e. downloads and
               installs new versions / updates.
* **help** - shows a help message.
* **version** - shows version of the program.
* **license** - shows license information for the program.
* **list-id** - prints a list of software IDs to the standard output. These IDs
                can be used to exculde certain software from updates. See the
                option --exclude below for more information.

### Options
Options can change behaviour of the update process. Available options are:

    --auto-get-newer | --newer | -n
      automatically tries to get information about newer versions of the soft-
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
      default timeout is 1800 seconds (30 minutes).
    --exclude ID | --except ID | -e ID
      Excludes the software with the given ID from the update process. To get
      the ID for a specific software, run the program with the --list-id
      option which lists all software IDs. You can use this option several
      times to exclude more than one software from the update process.
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

After that, open Visual Studio (2015 Community Edition or later recommended)
and just build the solution **updater/updater.sln** from the checked out
sources.

## Version history

A changelog is available in [changelog.md](./changelog.md).

## Copyright and Licensing

Copyright 2016, 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
