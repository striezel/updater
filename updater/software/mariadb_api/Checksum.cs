/*
    This file is part of the updater command line interface.
    Copyright (C) 2022  Dirk Stolle

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

namespace updater.software.mariadb_api
{
    /// <summary>
    /// Contains the checksum data of a file.
    /// </summary>
    internal class Checksum
    {
        /// <summary>
        /// SHA-1 checksum of the file
        /// </summary>
        public string sha1sum { get; set; }

        /// <summary>
        /// SHA-256 checksum of the file
        /// </summary>
        public string sha256sum { get; set; }

        /// <summary>
        /// SHA-512 checksum of the file
        /// </summary>
        public string sha512sum { get; set; }
    } // class
} // namespace
