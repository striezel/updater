/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2020, 2024  Dirk Stolle

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
using updater.cli;

namespace updater.operations
{
    /// <summary>
    /// Lists the IDs of software.
    /// </summary>
    public class IdList : IOperation
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="_opts">parameters / options from command line</param>
        public IdList(Options _opts)
        {
            opts = _opts;
            // no need to get newer versions, if user just wants the ID list
            opts.autoGetNewer = false;
        }


        public int perform()
        {
            var all = software.All.get(opts);
            foreach (var sw in all)
            {
                Console.WriteLine(sw.info().Name + ": " + string.Join(", ", sw.id()));
            } // foreach
            return 0;
        }


        /// <summary>
        /// all command line options parsed
        /// </summary>
        private readonly Options opts;
    } // class
} // namespace
