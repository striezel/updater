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

using System.Collections.Generic;
using System.Diagnostics;

namespace updater.utility
{
    /// <summary>
    /// utility class to handle process-related stuff
    /// </summary>
    public static class Processes
    {
        /// <summary>
        /// Checks whether any processes with the given names exist.
        /// </summary>
        /// <param name="names">list of process names (may be empty)</param>
        /// <returns>Returns true, if at least one matching process was found.
        /// Returns false otherwise.</returns>
        public static bool processesExist(List<string> names)
        {
            if (null == names)
                return false;
            foreach (var item in names)
            {
                int c = countAllByName(item);
                if (c > 0)
                    return true;
                if (c < 0)
                    throw new System.Exception("Could not check processes with name " + item + "!");
            }

            // No matching processes have been found.
            return false;
        }


        /// <summary>
        /// Counts the number of processes with the given name.
        /// </summary>
        /// <param name="name">name of the process(es)</param>
        /// <returns>Returns the number of existing processes with the given
        /// name in case of success. Returns -1 in case of failure.</returns>
        private static int countAllByName(string name)
        {
            try
            {
                Process[] processes = Process.GetProcessesByName(name);
                int result = processes.Length;
                processes = null;
                return result;
            }
            catch
            {
                return -1;
            }
        }
    } // class
} // namespace
