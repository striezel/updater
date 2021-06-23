/*
    This file is part of the updater command line interface.
    Copyright (C) 2021  Dirk Stolle

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

namespace updater.software.openjdk_api
{
    /// <summary>
    /// Contains binary information for an OpenJDK installer or package.
    /// </summary>
    internal class Binary
    {
        /// <summary>
        /// architecture of the installer or package
        /// </summary>
        public string architecture { get; set; }


        /// <summary>
        /// installer information
        /// </summary>
        public Installer installer { get; set; }


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="arch">initial architecture value</param>
        /// <param name="inst">initial installer value</param>
        public Binary(string arch = null, Installer inst = null)
        {
            architecture = arch;
            installer = inst;
        }
    }
}
