/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
using System.Collections.Generic;
using updater_cli.operations;

namespace updater_cli.cli
{
    /// <summary>
    /// holds program options that were given on the command line
    /// </summary>
    public class Options
    {
        public Options()
        {
            op = Operation.Unknown;
            autoGetNewer = true;
            withAurora = false;
            timeout = Update.defaultTimeout;
            excluded = new List<string>();
            pdf24autoUpdate = true;
            pdf24desktopIcons = true;
            pdf24faxPrinter = true;
        }


        /// <summary>
        /// operation that shall be performed
        /// </summary>
        public Operation op;

        /// <summary>
        /// whether to automatically get newer info about software
        /// </summary>
        public bool autoGetNewer;

        /// <summary>
        /// Whether or not Firefox Developer Edition (aurora channel) shall be
        /// included, too. Default is false, because this increases time of
        /// subsequent operations like getting the info() for every element in
        /// the list by quite a bit.
        /// </summary>
        public bool withAurora;

        /// <summary>
        /// maximum time in seconds to wait per update
        /// </summary>
        public uint timeout;

        /// <summary>
        /// list of software IDs that shall be excluded from the operation
        /// </summary>
        public List<string> excluded;

        /// <summary>
        /// whether PDF24 Creator shall enable automatic updates
        /// </summary>
        public bool pdf24autoUpdate;

        /// <summary>
        /// whether PDF24 Creator shall create desktop icons
        /// </summary>
        public bool pdf24desktopIcons;

        /// <summary>
        /// whether PDF24 Creator shall install fax printer
        /// </summary>
        public bool pdf24faxPrinter;
    } //class
} //namespace
