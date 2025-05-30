﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2024, 2025  Dirk Stolle

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
*/

using System;

namespace updater.operations
{
    /// <summary>
    /// Displays help message with info about parameters.
    /// </summary>
    public class Help : IOperation
    {
        public int perform()
        {
            Console.WriteLine("updater.exe operation [options]" + Environment.NewLine);
            Console.WriteLine("Operations:" + Environment.NewLine
                + "  Operations or commands define the main action of the program. Only one of\r\n"
                + "  these may be specified. Valid operations are:" + Environment.NewLine
                + Environment.NewLine
                + "  check   - Displays which installed software can be updated, but does not\r\n"
                + "            actually perform the updates." + Environment.NewLine
                + "  update  - Updates every software that can be updated, i.e. downloads and\r\n"
                + "            installs new versions / updates." + Environment.NewLine
                + "  help    - Shows this help message." + Environment.NewLine
                + "  version - Shows the version of the program." + Environment.NewLine
                + "  license - Shows license information for the program." + Environment.NewLine
                + "  list-id - Prints a list of software IDs to the standard output. These IDs\r\n"
                + "            can be used to exclude certain software from updates. See the\r\n"
                + "            option --exclude below for more information.\r\n"
                + Environment.NewLine
                + "Options:" + Environment.NewLine
                + "  Options can change behaviour of the update process. Available options are:\r\n"
                + Environment.NewLine
                + "  --auto-get-newer | --newer | -n" + Environment.NewLine
                + "      Automatically tries to get information about newer versions of the soft-\r\n"
                + "      ware from the internet. The updater has a list of known newest software\r\n"
                + "      versions, but that information can get outdated quickly. That is why\r\n"
                + "      this option exists - it helps to get the latest software version.\r\n"
                + "      The option is enabled by default.\r\n"
                + "  --no-auto-get-newer | --no-newer | -nn" + Environment.NewLine
                + "      Do not try to get information about newer software versions. It is not\r\n"
                + "      recommended to use this option, because it might mean that you get some\r\n"
                + "      slightly outdated updates.\r\n"
                + "  --timeout SECONDS | -t SECONDS" + Environment.NewLine
                + "      Sets the timeout in seconds for a single update process. If an update\r\n"
                + "      runs longer than the specified amount of seconds, it gets cancelled. The\r\n"
                + "      default timeout is " + Update.defaultTimeout.ToString() + " seconds.\r\n"
                + "  --exclude ID | --except ID | -e ID" + Environment.NewLine
                + "      Excludes the software with the given ID from the update process. To get\r\n"
                + "      the ID for a specific software, run the program with the list-id\r\n"
                + "      option which lists all software IDs. You can use this option several\r\n"
                + "      times to exclude more than one software from the update process.\r\n"
                + "  --show-progress | --progress | -p" + Environment.NewLine
                + "      Shows the download progress while downloading the updates. This is only\r\n"
                + "      relevant when the update operation was specified, it has no effect on\r\n"
                + "      other operations. Note that this can cause a very noisy output during\r\n"
                + "      downloads, because the progress may be updated several times per second.\r\n"
                + "  --pdf24-autoupdate" + Environment.NewLine
                + "      Enable automatic updates for PDF24 Creator after update. This option is\r\n"
                + "      enabled by default.\r\n"
                + "  --no-pdf24-autoupdate" + Environment.NewLine
                + "      Disable automatic updates for PDF24 Creator after update. This option is\r\n"
                + "      disabled by default.\r\n"
                + "  --pdf24-icons" + Environment.NewLine
                + "      Enable desktop icons for PDF24 Creator during update. This option is\r\n"
                + "      enabled by default.\r\n"
                + "  --no-pdf24-icons" + Environment.NewLine
                + "      Disable desktop icons for PDF24 Creator during update. This option is\r\n"
                + "      disabled by default.\r\n"
                + "  --pdf24-fax-printer" + Environment.NewLine
                + "      Installs the fax printer for PDF24 Creator during update. This option is\r\n"
                + "      enabled by default.\r\n"
                + "  --no-pdf24-fax-printer" + Environment.NewLine
                + "      Does not install the fax printer for PDF24 Creator during update. This\r\n"
                + "      option is disabled by default.");
            return 0;
        }
    } // class
} // namespace
