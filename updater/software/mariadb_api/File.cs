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
    /// Represents file information within a MariaDB release.
    /// </summary>
    internal class File
    {
#pragma warning disable IDE1006 // naming style
        /// <summary>
        /// Base name of the file download
        /// </summary>
        public string file_name { get; set; }

        /// <summary>
        /// type of package, e. g. "ZIP file", "gzipped tar file" or "MSI Package"
        /// </summary>
        public string package_type { get; set; }
        
        /// <summary>
        /// Generic name of the operating system, e. g. "Linux", "Windows", "Source"
        /// </summary>
        public string os { get; set; }
        
        /// <summary>
        /// CPU type for the download, e. g. "x86" or "x86_64"
        /// </summary>
        public string cpu { get; set; }

        /// <summary>
        /// checksum data for the file
        /// </summary>
        public Checksum checksum { get; set; }

        /// <summary>
        /// URL for the download
        /// </summary>
        public string file_download_url { get; set; }
#pragma warning restore IDE1006 // naming style
    }
}
