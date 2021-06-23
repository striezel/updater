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
    /// Contains installer information for an OpenJDK installer.
    /// </summary>
    internal class Installer
    {
        /// <summary>
        /// SHA-256 checksum of the installer
        /// </summary>
        public string checksum { get; set; }


        /// <summary>
        /// download link for the installer
        /// </summary>
        public string link { get; set; }


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="_chksum">initial value for checksum</param>
        /// <param name="_link">initial value for link</param>
        public Installer(string _chksum = null, string _link = null)
        {
            checksum = _chksum;
            link = _link;
        }
    }
}
